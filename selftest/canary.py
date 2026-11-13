#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests the self-test: serves the collector through a local proxy with planted faults, runs the endpoint and page
tests against the proxy, and checks that each fault is caught. The running collector is only read.

Planted faults:
  1. a script error on the first page of the menu
  2. the text "undefined" on the second page
  3. text under 11.5 px on every page (style sheet)
  4. a failing request: one API address the pages use answers 500
  5. a missing field: /api/now loses "site"
Usage: NETMON_CONFIG=/path/to/config.json python3 canary.py [proxy port, default 7791]
The page faults need macOS (webcheck); elsewhere only faults 4 and 5 are checked.
"""
import http.client
import http.server
import json
import os
import re
import socketserver
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import selftest as T                                         # noqa: E402

PROXY_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7791
WEB = os.path.join(T.APP, "web")
HTML, _ = T.page_scripts()
VIEWS = re.findall(r'data-view="([a-z]+)"', HTML)
SCRIPT = next(iter(re.findall(r'<script[^>]+src="/?([^"?]+\.js)', HTML)), "app.js")
STYLE = next(iter(re.findall(r'<link[^>]+href="/?([^"?]+\.css)', HTML)), "app.css")
API = [p for p in T.page_api_paths() if p not in ("/api/now", "/api/stream") and not p.startswith("/api/health/")]
BROKEN_API = API[0] if API else None
UI = sys.platform == "darwin" and len(VIEWS) >= 2


def planted_js():
    s = open(os.path.join(WEB, SCRIPT), "rb").read()
    v1, v2 = (VIEWS + ["", ""])[:2]
    s += ("\n;(() => { const plant = () => {"
          f" if (location.hash === '#/{v1}') setTimeout(() => {{ throw new Error('canary: planted error'); }}, 50);"
          f" if (location.hash === '#/{v2}') setTimeout(() => {{ const m = document.querySelector({json.dumps(T.ST.get('page_container', '#view'))});"
          " if (m) { const p = document.createElement('p'); p.textContent = 'undefined ms'; m.appendChild(p); } }, 50); };"
          " addEventListener('hashchange', plant); addEventListener('load', plant); })();\n").encode()
    return s


def planted_css():
    sel = T.ST.get("page_container", "#view")
    return open(os.path.join(WEB, STYLE), "rb").read() + f"\n{sel} p {{ font-size: 9px !important; }}\n".encode()


class P(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/" + SCRIPT:
            return self.out(200, planted_js(), "text/javascript")
        if path == "/" + STYLE:
            return self.out(200, planted_css(), "text/css")
        if BROKEN_API and path == BROKEN_API:
            return self.out(500, b'{"error":"canary"}', "application/json")
        c = http.client.HTTPConnection("127.0.0.1", T.PORT, timeout=60)
        c.request("GET", self.path, headers={"Host": T.HOST, "Accept": self.headers.get("Accept", "*/*")})
        r = c.getresponse()
        if path == "/api/stream":
            self.send_response(r.status)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            try:
                while True:
                    b = r.read1(65536)
                    if not b:
                        break
                    self.wfile.write(b)
                    self.wfile.flush()
            except OSError:
                pass
            return
        b = r.read()
        if path == "/api/now":
            d = json.loads(b)
            d.pop("site", None)
            b = json.dumps(d).encode()
        self.out(r.status, b, r.getheader("Content-Type") or "application/octet-stream")

    def out(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    srv = S(("127.0.0.1", PROXY_PORT), P)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    T.BASE = f"http://127.0.0.1:{PROXY_PORT}"
    R = T.Run()
    T.layer_endpoints(R, {})
    if UI:
        T.layer_pages(R)
    st = {r["id"]: r for r in R.results}
    expect = [("api.now", "FAIL", "site")]
    if BROKEN_API:
        expect.append((f"api.{BROKEN_API[5:]}", "FAIL", "500"))
    if UI:
        expect += [(f"ui.{VIEWS[0]}", "FAIL", "canary: planted error"), (f"ui.{VIEWS[1]}", "FAIL", "undefined")]
    caught = 0
    for tid, want, word in expect:
        r = st.get(tid, {})
        hit = r.get("status") == want and word in r.get("detail", "")
        caught += hit
        print(f"{'CAUGHT' if hit else 'MISSED'}  {tid:16} expected {want} mentioning '{word}': got {r.get('status')} {r.get('detail', '')[:150]}")
    if UI:
        tiny = any("under 11.5 px" in r.get("detail", "") for r in R.results if r["id"].startswith("ui."))
        caught += tiny
        expect.append(("ui.*", "WARN", "under 11.5 px"))
        print(f"{'CAUGHT' if tiny else 'MISSED'}  ui.*             expected text under 11.5 px on some page")
    ids = {e[0] for e in expect}
    others = [r for r in R.results if r["status"] == "FAIL" and r["id"] not in ids]
    for r in others:
        print(f"EXTRA   {r['id']:16} {r['detail'][:150]}")
    print(f"canary: {caught} of {len(expect)} planted faults caught, {len(others)} other failures")
    srv.shutdown()
    return 0 if caught == len(expect) else 1


if __name__ == "__main__":
    sys.exit(main())
