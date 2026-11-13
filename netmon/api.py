# SPDX-License-Identifier: AGPL-3.0-or-later
"""HTTP server: every /api route, the live event stream, the health push endpoints and the web files.

Touches: listens on CFG["collector"]["bind"]:CFG["collector"]["port"]; reads files under <repo>/web.

Access rules:
  - every request must come from an address in CFG["collector"]["allow"];
  - the Host header must name this collector (DNS-rebinding guard): its name, localhost, its own
    addresses, or an entry of CFG["collector"]["hosts"], with the port;
  - POST requests also need the header X-Netmon: 1 and, when present, a matching Origin;
  - /api/health/report and /api/health/installer skip the allow list and check per-machine
    addresses and tokens instead (health.py).
At most 64 requests run at once and at most 8 live streams stay open.
"""
import http.server
import ipaddress
import json
import os
import socket
import socketserver
import threading
from urllib.parse import parse_qs, urlparse

from . import config, health, views, views_security as sec, views_traffic as tr
from .config import CFG
from .state import LOG, STOP

GET = {"/api/now": views.api_now, "/api/series": views.api_series, "/api/latency": views.api_latency,
       "/api/devices": views.api_devices, "/api/device": views.api_device, "/api/apps": views.api_apps,
       "/api/conns": views.api_conns, "/api/dns": views.api_dns, "/api/checks": views.api_checks,
       "/api/geo": tr.api_geo, "/api/skyline": views.api_skyline, "/api/privacy": tr.api_privacy,
       "/api/ports": tr.api_ports, "/api/beacons": tr.api_beacons, "/api/air": tr.api_air, "/api/mind": views.api_mind,
       "/api/threats": sec.api_threats, "/api/dpi": sec.api_dpi, "/api/vpn": sec.api_vpn, "/api/mind/live": views.api_mind,
       "/api/isp": sec.api_isp, "/api/vpnswitch": sec.api_vpnswitch, "/api/tunnel": sec.api_tunnel,
       "/api/vpncost": sec.api_vpncost, "/api/names": tr.api_names, "/api/health": sec.api_health,
       "/api/navorder": views.api_navorder, "/api/bloat": tr.api_bloat, "/api/dnsspeed": tr.api_dnsspeed,
       "/api/timeline": views.api_timeline, "/api/selftest": views.api_selftest, "/api/crypto": tr.api_crypto,
       "/api/rhythm": tr.api_rhythm, "/api/companies": tr.api_companies, "/api/pulse": tr.api_pulse}
POST = {"/api/device/label": views.api_label, "/api/device/known": views.api_known, "/api/check/run": views.api_runcheck,
        "/api/dpi/capture": sec.api_dpi_capture, "/api/vpn/expect": sec.api_vpn_expect, "/api/isp/capture": sec.api_isp_capture,
        "/api/vpnswitch": sec.api_vpnswitch_set, "/api/navorder": views.api_navorder_set, "/api/bloat/test": sec.api_bloattest,
        "/api/selftest/run": views.api_selftest_run}
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml",
        ".png": "image/png", ".webmanifest": "application/manifest+json", ".json": "application/json", ".woff2": "font/woff2"}
WEB = os.path.realpath(os.path.join(config.ROOT, "web"))
SSE_SLOTS = threading.BoundedSemaphore(8)
ACCESS = {"allow": [], "hosts": set()}


def build_access():
    """The allow list and the Host names this collector answers to."""
    from .dns import collector_addrs
    c = CFG["collector"]
    ACCESS["allow"] = [ipaddress.ip_network(str(n), strict=False) for n in c.get("allow") or []]
    port = c["port"]
    names = {"localhost", "127.0.0.1", "[::1]", *collector_addrs(), *(c.get("hosts") or [])}
    for n in {c.get("name") or "", socket.gethostname().split(".")[0]}:
        if n:
            names |= {n, f"{n}.local", f"{n}.lan", f"{n}.home.arpa"}
    try:
        names.add(socket.gethostname())
    except OSError:
        pass
    hosts = {f"{h}:{port}".lower() for h in names if h}
    if port == 80:
        hosts |= {h.lower() for h in names if h}
    ACCESS["hosts"] = hosts


class Handler(http.server.BaseHTTPRequestHandler):
    CLIENT_GONE = (BrokenPipeError, ConnectionResetError)
    server_version = "netmon"
    timeout = 30

    def handle(self):
        try:
            super().handle()
        except self.CLIENT_GONE:
            pass

    def log_message(self, fmt, *args):
        pass

    def peer(self):
        try:
            return ipaddress.ip_address(self.client_address[0].replace("::ffff:", ""))
        except ValueError:
            return None

    def host_ok(self):
        return (self.headers.get("Host") or "").lower() in ACCESS["hosts"]

    def peer_ok(self):
        ip = self.peer()
        return ip is not None and any(ip in n for n in ACCESS["allow"] if n.version == ip.version)

    def send(self, code, body, ctype="application/json", cache="no-store"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, separators=(",", ":"), default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", cache)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/health/installer":
            if not self.host_ok():
                return self.send(403, b"Not allowed.", "text/plain")
            body = health.health_installer(parse_qs(u.query).get("m", [""])[0], self.peer())
            return self.send(200, body.encode(), "text/plain; charset=utf-8") if body else \
                self.send(404, b"No installer waiting for this machine.", "text/plain")
        if not self.peer_ok():
            return self.send(403, b"This device is not on the allow list.", "text/plain")
        if not self.host_ok():
            c = CFG["collector"]
            return self.send(403, f"Open {config.BRAND} by the collector's own name or address, for example "
                                  f"http://{c.get('name') or 'localhost'}:{c['port']}".encode(), "text/plain")
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/api/stream":
            return self.stream()
        if u.path in GET:
            try:
                return self.send(200, GET[u.path](q))
            except self.CLIENT_GONE:
                return
            except Exception as e:
                LOG.exception("api %s", u.path)
                return self.send(500, {"error": str(e)})
        if u.path.startswith("/api/"):
            return self.send(404, {"error": "Not found."})
        path = "/index.html" if u.path in ("/", "") else u.path
        f = os.path.realpath(os.path.join(WEB, path.lstrip("/")))
        if os.path.commonpath([f, WEB]) != WEB or not os.path.isfile(f):
            return self.send(404, b"Not found", "text/plain")
        ext = os.path.splitext(f)[1]
        with open(f, "rb") as fh:
            self.send(200, fh.read(), MIME.get(ext, "application/octet-stream"),
                      "no-cache" if ext in (".html", ".js", ".css") else "max-age=86400")

    def do_POST(self):
        if urlparse(self.path).path == "/api/health/report":
            if not self.host_ok():
                return self.send(403, {"error": "Not allowed."})
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if not 0 < n <= 65536:
                    raise ValueError("report must be 1 to 65536 bytes")
                code, res = health.api_health_report(self.peer(), self.headers, self.rfile.read(n))
            except Exception as e:
                code, res = 400, {"error": str(e)[:200]}
            return self.send(code, res)
        origin = (self.headers.get("Origin") or "").lower()
        origin_host = origin.split("://", 1)[-1] if origin else ""
        if not (self.peer_ok() and self.host_ok()) or self.headers.get("X-Netmon") != "1" or \
                (origin and origin_host not in ACCESS["hosts"]):
            return self.send(403, {"error": "Not allowed."})
        u = urlparse(self.path)
        if u.path not in POST:
            return self.send(404, {"error": "Not found."})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if not 0 <= n <= 10_000:
                raise ValueError("body must be 0 to 10000 bytes")
            body = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("body must be a JSON object")
            return self.send(200, POST[u.path]({}, body))
        except Exception as e:
            return self.send(400, {"error": str(e)})

    def stream(self):
        """Server-sent events: the /api/now payload every vitals interval."""
        if not SSE_SLOTS.acquire(blocking=False):
            return self.send(503, {"error": "Too many open live views."})
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            while not STOP.is_set():
                self.wfile.write(b"data: " + json.dumps(views.api_now({}), default=str).encode() + b"\n\n")
                self.wfile.flush()
                STOP.wait(CFG["router"].get("vitals_every_s", 10))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            LOG.exception("stream")
        finally:
            SSE_SLOTS.release()


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    SLOTS = threading.BoundedSemaphore(64)

    def process_request(self, request, client_address):
        if not self.SLOTS.acquire(blocking=False):
            return self.shutdown_request(request)
        try:
            super().process_request(request, client_address)
        except Exception:
            self.SLOTS.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.SLOTS.release()

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = CFG["collector"].get("name") or "netmon", self.server_address[1]


def make_server():
    """Binds the configured address; falls back to IPv4 when IPv6 is not available."""
    build_access()
    bind, port = CFG["collector"].get("bind") or "::", CFG["collector"]["port"]
    fam = socket.AF_INET6 if ":" in bind else socket.AF_INET
    try:
        cls = type("Server6" if fam == socket.AF_INET6 else "Server4", (Server,), {"address_family": fam})
        return cls((bind, port), Handler)
    except OSError as e:
        if fam != socket.AF_INET6 or e.errno in (48, 98):
            raise
        LOG.warning("IPv6 bind failed (%s); listening on IPv4 only", e)
        cls = type("Server4", (Server,), {"address_family": socket.AF_INET})
        return cls(("0.0.0.0", port), Handler)
