#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""netmon self-test: checks on a schedule that the collector, the router and the network behind it work.

TWO KINDS OF TEST
  Deterministic  an exact answer is known and must come back: an endpoint answers with the right fields, a lock
                 refuses a stranger, a router setting equals the blessed value, a sample input parses to the
                 known result, a page loads with no script error.
  Heuristic      no exact answer exists, so the test judges plausibility: data is fresh, latency is normal for
                 this network, a count has not collapsed against its own recent history, the log is quiet.

LAYERS
  code       the program's own parts, with fixed inputs whose answers are known
  endpoints  every address the pages use answers quickly with the fields they need
  locks      strangers, forged requests, path tricks and unlisted router commands are refused
  router     the router's netmon files and shaper settings equal the blessed copy; gate output follows the contract
  vpn        the VPN switch, the tunnel and the DNS path agree (only when config "vpn.enabled" is true)
  fresh      every table the collector writes is still growing
  pages      every page opens in a real browser with no script error (macOS only: uses webcheck.swift)
  sense      numbers look normal against this network's own history

WHAT IT TOUCHES
  Read-only everywhere. The browser check blocks every write the pages could make. The only requests that are
  not plain reads are deliberately forged or malformed writes that the collector must refuse. The router is
  asked through netmon-gate with read-only subcommands, plus one unlisted command that the gate must refuse.

CONFIGURATION
  The same config.json as the collector: path from the environment variable NETMON_CONFIG, else ./config.json.
  Optional "selftest" section:
    {"db": "<collector database path>", "data_dir": "", "queue_dir": "",
     "dns_probe": {"server": "<ip>", "allowed": "example.com",
     "blocked": "<a name the DNS filter blocks>"}, "direct_exit_cidrs": ["<the ISP's public ranges>"],
     "write_probe": "/api/navorder", "latency_floor_ms": {"<target>": 15}, "digest_hour": 7,
     "page_container": "#view", "db_cap_gb": 20,
     "fresh_tables": [["<table>", "<time column>", <seconds between rows>, "<description>"]]}

WHERE IT WRITES
  selftest.data_dir (default <collector.data_dir>/selftest/): selftest.db (history), latest.json (what the
  Self-test page shows), manifest.json (the blessed file hashes and router settings).
  selftest.queue_dir (default selftest/queue/ in the repository): a file here starts a run at once.

ALERTS
  A test that fails twice in a row (once, for the tests marked urgent) is queued for a daily summary email,
  sent through the collector's own mail code (netmon/alerts.py) to config "alerts.email_to". With no address
  set it only prints. Warnings never email.

USE
  selftest.py run          full run (the scheduler runs this every 15 minutes)
  selftest.py quick        code, endpoints and locks only, no browser, no alerts (use before and after a deploy)
  selftest.py bless        record the current files and router settings as correct (after a deliberate change)
  selftest.py precheck D   import the netmon package from directory D without starting it; exit 1 if it would not
                           start. Use it on a candidate tree before replacing the running one.
Standard library only.
"""
import builtins
import datetime
import fcntl
import glob
import hashlib
import ipaddress
import json
import os
import random
import re
import socket
import sqlite3
import statistics
import struct
import subprocess
import symtable
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(HERE)                                  # the repository root
sys.path.insert(0, APP)


# ---------------------------------------------------------------- configuration


def load_config():
    path = os.environ.get("NETMON_CONFIG") or os.path.join(os.getcwd(), "config.json")
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["_path"] = os.path.abspath(path)
    return cfg


CFG = load_config()
COL = CFG.get("collector", {})
ROUTER = CFG.get("router", {})
ST = CFG.get("selftest", {})
PORT = int(COL.get("port", 7780))
BASE = f"http://127.0.0.1:{PORT}"
HOST = f"127.0.0.1:{PORT}"
DATA_ROOT = COL.get("data_dir", "/var/lib/netmon")
DBPATH_NETMON = ST.get("db") or os.path.join(DATA_ROOT, "netmon.db")
DATA = ST.get("data_dir") or os.path.join(DATA_ROOT, "selftest")
DBPATH = os.path.join(DATA, "selftest.db")
LATEST = os.path.join(DATA, "latest.json")
MANIFEST = os.path.join(DATA, "manifest.json")
QUEUE = ST.get("queue_dir") or os.path.join(HERE, "queue")
DIGEST = os.path.join(DATA, "digest_pending.jsonl")
DIGEST_SENT = os.path.join(DATA, "digest_last_sent.txt")
VPN_ON_CFG = bool(CFG.get("vpn", {}).get("enabled"))

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS runs(ts INT PRIMARY KEY, secs REAL, pass INT, warn INT, fail INT, skip INT, how TEXT);
CREATE TABLE IF NOT EXISTS results(ts INT, id TEXT, status TEXT, detail TEXT, PRIMARY KEY(ts, id)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS state(id TEXT PRIMARY KEY, status TEXT, streak INT, hard TEXT, since INT);
CREATE TABLE IF NOT EXISTS metrics(ts INT, k TEXT, v REAL, PRIMARY KEY(ts, k)) WITHOUT ROWID;
"""

LAYERS = [("code", "Code", "The program's own parts, tested with fixed inputs whose answers are known."),
          ("endpoints", "Endpoints", "Every data address the pages use answers quickly, with the fields the pages need."),
          ("locks", "Locks", "Strangers, forged requests and path tricks are refused, on the collector and on the router."),
          ("router", "Router", "The router's netmon files and shaper settings are as blessed, and its answers follow the gate contract."),
          ("vpn", "VPN and DNS", "The VPN switch, the tunnel, the exit address and the DNS path all agree."),
          ("fresh", "Freshness", "Every collector is still writing, and every check is still running."),
          ("pages", "Pages", "Every page opens in a real browser with no script error and readable text."),
          ("sense", "Plausibility", "Numbers look normal for this network against their own recent history.")]


# ---------------------------------------------------------------- results


class Run:
    def __init__(self):
        self.results = []
        self.metrics = {}

    def add(self, layer, tid, title, status, detail="", kind="deterministic", urgent=False):
        self.results.append({"layer": layer, "id": tid, "title": title, "status": status,
                             "detail": str(detail)[:600], "kind": kind, "urgent": urgent})

    def test(self, layer, tid, title, fn, kind="deterministic", urgent=False):
        """fn returns (status, detail). An exception is a FAIL with the error as detail."""
        t = time.time()
        try:
            st, detail = fn()
        except Exception as e:                               # a broken test shows up as a failure
            st, detail = "FAIL", f"The test itself failed: {e.__class__.__name__}: {e}"
        self.add(layer, tid, title, st, detail, kind, urgent)
        self.results[-1]["ms"] = int((time.time() - t) * 1000)

    def metric(self, k, v):
        if v is not None:
            self.metrics[k] = float(v)


def ok(d=""): return "PASS", d
def warn(d): return "WARN", d
def fail(d): return "FAIL", d
def skip(d): return "SKIP", d


# ---------------------------------------------------------------- helpers


def http(path, host=None, method="GET", headers=None, body=None, base=None, timeout=30):
    """(status, headers, body bytes, ms). Never raises for HTTP errors."""
    host, base = host or HOST, base or BASE
    h = {"Host": host}
    h.update(headers or {})
    req = urllib.request.Request(base + path, data=body, headers=h, method=method)
    t = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, dict(r.headers), r.read(), (time.time() - t) * 1000
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(), (time.time() - t) * 1000


def raw_http(addr, text, timeout=10):
    """Send a hand-written request (for requests urllib will not make) and return the status code."""
    s = socket.create_connection((addr, PORT), timeout=timeout)
    try:
        s.sendall(text.encode())
        first = s.recv(200).decode("latin-1").split("\r\n")[0]
        return int(first.split()[1]) if first.startswith("HTTP/") else 0
    finally:
        s.close()


def getj(path):
    st, _, b, ms = http(path)
    if st != 200:
        raise RuntimeError(f"{path} answered {st}")
    return json.loads(b)


def sha(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def ndb():
    """Read-only connection to the collector's database."""
    return sqlite3.connect(f"file:{DBPATH_NETMON}?mode=ro", uri=True, timeout=20)


def has_table(c, t):
    return c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (t,)).fetchone() is not None


def hm(ts):
    """Local time of day, HH:MM, or ? for no time."""
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M") if ts else "?"


def ago(s):
    s = int(s)
    return f"{s} s" if s < 120 else f"{s // 60} min" if s < 7200 else f"{s // 3600} h"


def router_set():
    return bool(ROUTER.get("ssh") or ROUTER.get("ip"))


def gate(cmd, timeout=30):
    """Run one netmon-gate subcommand on the router over SSH, the way the collector does: (exit code, stdout)."""
    target = ROUTER.get("ssh") or f"root@{ROUTER['ip']}"
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=6"]
    if ROUTER.get("key"):
        ssh += ["-i", os.path.expanduser(ROUTER["key"]), "-o", "IdentitiesOnly=yes"]
    ssh += [str(x) for x in ROUTER.get("ssh_options") or []]
    p = subprocess.run(ssh + [target, f"{ROUTER.get('gate', '/usr/bin/netmon-gate')} {cmd}"],
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout


def gate_lines(cmd):
    rc, out = gate(cmd)
    if rc != 0:
        raise RuntimeError(f"the router gate refused '{cmd}' (exit {rc}): {out.strip()[:120]}")
    return [l.split("|") for l in out.splitlines() if l.strip()]


def unit(s):
    """'32Mbit' -> 32e6 bit/s, '1.5ms' -> 1500 us, '2Kb' -> 2048 bytes; None when it does not parse."""
    m = re.fullmatch(r"([0-9.]+)(Gbit|Mbit|Kbit|bit|ms|us|s|Gb|Mb|Kb|b)", s or "")
    if not m:
        return None
    mult = {"bit": 1, "Kbit": 1e3, "Mbit": 1e6, "Gbit": 1e9, "us": 1, "ms": 1e3, "s": 1e6,
            "b": 1, "Kb": 1024, "Mb": 1024 ** 2, "Gb": 1024 ** 3}[m.group(2)]
    return float(m.group(1)) * mult


def repo_files():
    """Every file of the program whose change means the running system changed."""
    pats = ["netmon.py", "dpi.py", "netmon/*.py", "web/*", "health/*.sh", "selftest/*.py", "selftest/*.swift", "router/*"]
    out = []
    for p in pats:
        out += [os.path.relpath(f, APP) for f in glob.glob(os.path.join(APP, p)) if os.path.isfile(f)]
    return sorted(set(out))


def py_files():
    return [f for f in repo_files() if f.endswith(".py")]


# ---------------------------------------------------------------- gate contract (formats from docs/ADAPTING.md)


def check_vitals(text):
    """Problems with a 'vitals' answer, or [] when it follows the contract."""
    d = json.loads(text.strip().splitlines()[0])
    want = {"ts": int, "uptime": int, "load": list, "cpu": list, "temp_mc": int, "mem_total_kb": int,
            "mem_avail_kb": int, "conntrack": list, "wifi_clients": int, "netifyd_rss_kb": int,
            "dns_upstream": str, "ifaces": dict}
    bad = [f"no '{k}'" for k in want if k not in d]
    bad += [f"'{k}' is {type(d[k]).__name__}" for k, t in want.items() if k in d and not isinstance(d[k], t)]
    bad += [f"interface {k} is not [rx, tx]" for k, v in d.get("ifaces", {}).items()
            if not (isinstance(v, list) and len(v) == 2)]
    return bad


DNSLOG_STATUS = {"forwarded", "cached", "blocked", "other"}


def check_dnslog(text):
    bad = []
    for n, line in enumerate(l for l in text.splitlines() if l.strip()):
        d = json.loads(line)
        if not {"ts", "client", "domain", "qtype", "status"} <= set(d) <= {"ts", "client", "domain", "qtype", "status", "answers", "reply_ms"}:
            bad.append(f"line {n + 1} has fields {sorted(d)}")
        elif "answers" in d and not (isinstance(d["answers"], list) and all(ipaddress.ip_address(a) for a in d["answers"])):
            bad.append(f"line {n + 1} has bad answers")
        elif not isinstance(d["ts"], int) or d["status"] not in DNSLOG_STATUS or not d["domain"]:
            bad.append(f"line {n + 1} has a bad value: {line[:80]}")
        else:
            ipaddress.ip_address(d["client"])
    return bad


def check_lines(text, kinds):
    """Line-format answers (links, health, integrity): kind|field|... with the minimum field count per kind."""
    bad, seen = [], set()
    for n, line in enumerate(l for l in text.splitlines() if l.strip()):
        f = line.split("|")
        if f[0] not in kinds:
            continue
        seen.add(f[0])
        if len(f) - 1 < kinds[f[0]]:
            bad.append(f"line {n + 1} ({f[0]}) has {len(f) - 1} fields, needs {kinds[f[0]]}")
    return bad, seen


LINKS_KINDS = {"wifi": 4, "arp": 3, "port": 12, "fdb": 3}
HEALTH_KINDS = {"v": 2, "host": 2, "os": 2, "uptime": 1, "load": 3, "mem": 2, "disk": 5, "temp": 2, "posture": 2}
INTEGRITY_KINDS = {"v": 2, "file": 3, "sqm": 7, "qdisc": 3, "ctinfo": 2, "mangle": 3, "natdns": 1, "vpndns": 1}


def check_vpn_status(text):
    d = json.loads(text.strip())
    want = ("enabled", "rule", "peer", "handshake", "transfer", "now", "dns", "endpoint")
    return [f"no '{k}'" for k in want if k not in d]


def check_leases(text):
    bad = []
    for n, line in enumerate(l for l in text.splitlines() if l.strip() and not l.startswith("#")):
        f = line.split()
        if len(f) < 4 or not f[0].isdigit() or not re.fullmatch(r"[0-9a-f:]{17}", f[1].lower()):
            bad.append(f"line {n + 1} is not '<expiry> <mac> <ip> <name> ...'")
    return bad


def parse_cake(text):
    """{device: {"bw": bit/s, "tins": {name: {...}}, "names": [...]}} from the gate's 'cake' answer."""
    out, dev, names = {}, None, []
    for line in text.splitlines():
        if line.startswith("## "):
            dev = line[3:].strip()
            out[dev] = {"bw": None, "tins": {}, "names": []}
            continue
        if dev is None:
            continue
        m = re.search(r"qdisc cake .*?bandwidth (\S+)", line)
        if m:
            out[dev]["bw"] = unit(m.group(1))
        elif re.match(r"^\s{10,}\S", line) and not re.match(r"^\s+(thresh|target|interval)", line) and "  " in line.strip():
            names = re.split(r"\s{2,}", line.strip())
            out[dev]["names"] = names
            out[dev]["tins"] = {n: {} for n in names}
        elif out[dev]["names"] and re.match(r"^\s+[a-z_]+\s", line):
            f = line.split()
            for n, v in zip(out[dev]["names"], f[1:]):
                out[dev]["tins"][n][f[0]] = v
    return out


# ---------------------------------------------------------------- code (deterministic, fixed inputs)


def undefined_globals(path):
    """Names a function uses that nothing defines: errors that only show when that function runs."""
    src = open(path, encoding="utf-8").read()
    top = symtable.symtable(src, path, "exec")
    defined = set(dir(builtins)) | {"__file__", "__name__", "__doc__", "__builtins__", "__spec__", "__path__",
                                     "__package__", "__loader__"}
    tables = [top]
    while tables:
        t = tables.pop()
        for s in t.get_symbols():
            if (t is top and (s.is_assigned() or s.is_imported() or s.is_namespace())) or \
               (s.is_declared_global() and s.is_assigned()):
                defined.add(s.get_name())
        tables.extend(t.get_children())
    missing = set()
    tables = list(top.get_children())
    while tables:
        t = tables.pop()
        for s in t.get_symbols():
            if s.is_global() and s.is_referenced() and s.get_name() not in defined:
                missing.add(f"{s.get_name()} (in {t.get_name()})")
        tables.extend(t.get_children())
    return sorted(missing)


def fixture(name):
    with open(os.path.join(HERE, "fixtures", name), encoding="utf-8") as f:
        return f.read()


def pcap(packets):
    """A little-endian Ethernet pcap from [(ts, ip packet bytes)]."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, ip in packets:
        frame = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00" + ip
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)) + frame
    return out


def ipv4(src, dst, proto, l4):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + l4


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def client_hello(sni):
    """A minimal TLS 1.3 ClientHello carrying the server name sni."""
    name = sni.encode()
    sni_ext = struct.pack("!HH", 0, len(name) + 5) + struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    ver_ext = struct.pack("!HHB", 43, 3, 2) + b"\x03\x04"
    exts = sni_ext + ver_ext
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" + struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def layer_code(R):
    L = "code"
    for f in py_files():
        def t(f=f):
            p = os.path.join(APP, f)
            compile(open(p, encoding="utf-8").read(), p, "exec")
            miss = undefined_globals(p)
            return fail("Uses names nothing defines: " + ", ".join(miss[:8])) if miss else ok("Compiles; every name it uses is defined.")
        R.test(L, f"code.names.{f}", f"{f} compiles, and every name it uses exists", t)

    def dpi_sigs():
        import dpi
        bad = []
        ch = dpi.tls_client_hello(client_hello("www.example.com"))
        if not ch or ch["sni"] != "www.example.com" or not ch["tls13"]:
            bad.append(f"the TLS ClientHello read as {ch}")
        cases = [("udp", 50000, 51820, b"\x01\x00\x00\x00" + b"\x00" * 144, 148, "WireGuard"),
                 ("udp", 50000, 3478, b"\x00\x01\x00\x00\x21\x12\xa4\x42" + b"\x00" * 12, 20, "STUN"),
                 ("udp", 50000, 443, b"\xc3\x00\x00\x00\x01" + b"\x00" * 40, 45, "QUIC"),
                 ("tcp", 50000, 22, b"SSH-2.0-Example_1.0\r\n", 21, "SSH"),
                 ("tcp", 50000, 80, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", 37, "HTTP (unencrypted)"),
                 ("udp", 50000, 53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", 12, "DNS (unencrypted)")]
        for proto, sp, dp, p, plen, want in cases:
            got = dpi.signature(proto, sp, dp, p, plen)[0]
            if got != want:
                bad.append(f"{want} sample read as {got}")
        return fail("; ".join(bad)) if bad else ok(f"A TLS ClientHello and {len(cases)} protocol samples are recognised.")
    R.test(L, "code.dpi.signatures", "Traffic fingerprints recognise known protocol samples", dpi_sigs)

    def dpi_flows():
        import dpi
        t0 = 1_700_000_000.0
        pk = [(t0 + i * 0.02, ipv4("192.168.1.10", "198.51.100.7", 17, udp(40000, 51820, (b"\x04\x00\x00\x00" + b"\x00" * 108)
                                                                            if i else (b"\x01\x00\x00\x00" + b"\x00" * 144))))
              for i in range(30)]
        r = dpi.analyse(pcap(pk))
        f = r["flows"]
        if len(f) != 1:
            return fail(f"30 packets of one flow gave {len(f)} flows.")
        f = f[0]
        bad = [] if f["label"] == "WireGuard" and f["tunnel"] and f["lan"] == "192.168.1.10" and f["pkts"] == 30 \
            else [f"read as {f['label']}, tunnel {f['tunnel']}, local side {f['lan']}, {f['pkts']} packets"]
        return fail("; ".join(bad)) if bad else ok("A synthetic WireGuard capture reads as one tunnel flow of 30 packets.")
    R.test(L, "code.dpi.flows", "A capture is grouped into flows and labelled", dpi_flows)

    def contract():
        bad = []
        for name, fn in (("vitals.json", check_vitals), ("dnslog.jsonl", check_dnslog),
                         ("vpn_status.json", check_vpn_status), ("leases.txt", check_leases)):
            bad += [f"{name}: {b}" for b in fn(fixture(name))]
        for name, kinds in (("links.txt", LINKS_KINDS), ("health_router.txt", HEALTH_KINDS), ("integrity.txt", INTEGRITY_KINDS)):
            b, seen = check_lines(fixture(name), kinds)
            bad += [f"{name}: {x}" for x in b]
            if not seen:
                bad.append(f"{name}: no known line kinds")
        for fn, junk in ((check_dnslog, '{"ts":"x","client":"1.2.3.4"}\n'), (check_leases, "garbage line\n"),
                         (check_vitals, '{"ts": 1}')):
            try:
                if not fn(junk):
                    bad.append(f"{fn.__name__} accepted junk")
            except (ValueError, KeyError, TypeError):
                pass
        return fail("; ".join(bad)) if bad else ok("Every saved gate answer follows the contract, and junk is rejected.")
    R.test(L, "code.contract", "The gate contract checks accept good answers and reject junk", contract)

    def cake():
        d = parse_cake(fixture("cake.txt"))
        want = {"eth1": 40e6, "ifb4eth1": 90e6}
        bad = [f"{k}: {d.get(k, {}).get('bw')} not {v}" for k, v in want.items() if d.get(k, {}).get("bw") != v]
        bad += [f"{k}: tier names {d.get(k, {}).get('names')}" for k in want
                if d.get(k, {}).get("names") != ["Bulk", "Best Effort", "Video", "Voice"]]
        return fail("; ".join(bad)) if bad else ok("A saved shaper report reads as 2 shapers with 4 tiers each, at 40 and 90 Mbit/s.")
    R.test(L, "code.cake", "Shaper reports from the router are read correctly", cake)

    def units():
        cases = [("32Mbit", 32e6), ("73Mbit", 73e6), ("1.5ms", 1500), ("12us", 12), ("2Kb", 2048), ("0bit", 0), ("bogus!", None)]
        bad = [f"{a} gave {unit(a)}, expected {e}" for a, e in cases if unit(a) != e]
        return fail("; ".join(bad)) if bad else ok("Router speeds, delays and sizes convert correctly.")
    R.test(L, "code.units", "Router units convert correctly", units)

    def health_script():
        p = subprocess.run(["/bin/sh", os.path.join(APP, "health", "netmon-health.sh")], capture_output=True, text=True, timeout=180)
        b, seen = check_lines(p.stdout, HEALTH_KINDS)
        need = {"v", "host", "os", "uptime", "load", "mem"}
        if p.returncode or b or need - seen:
            return fail(f"exit {p.returncode}; " + "; ".join(b + [f"missing {sorted(need - seen)}"])[:400])
        return ok(f"The health reporter runs here and prints {len(p.stdout.splitlines())} well-formed facts.")
    R.test(L, "code.health", "The machine health reporter runs and follows its format", health_script)


# ---------------------------------------------------------------- endpoints (deterministic contracts)

NOW_SPEC = "now:n site:d"
SITE_SPEC = ("name", "short", "router", "uplink", "isp", "zones")
TYPES = {"n": (int, float), "s": str, "l": list, "d": dict, "b": bool}
SLOW_MS = 4000


def page_scripts():
    idx = os.path.join(APP, "web", "index.html")
    if not os.path.exists(idx):
        return "", []
    html = open(idx, encoding="utf-8").read()
    js = ""
    for f in glob.glob(os.path.join(APP, "web", "*.js")):
        js += open(f, encoding="utf-8").read() + "\n"
    return html, js


def page_api_paths():
    """Every /api address the pages call, as written in the web files."""
    _, js = page_scripts()
    return sorted({"/" + p.rstrip("/?") for p in re.findall(r"api/[a-z][a-z/]*", js or "")})


def check_fields(d, spec):
    bad = []
    for f in spec.split():
        k, ty = f.split(":")
        if k not in d:
            bad.append(f"no '{k}'")
        elif ty != "*" and not isinstance(d[k], TYPES[ty]):
            bad.append(f"'{k}' is {type(d[k]).__name__}")
    return bad


def layer_endpoints(R, keep):
    L = "endpoints"

    def now():
        st, hd, b, ms = http("/api/now", timeout=60)
        if st != 200:
            return fail(f"Answered {st}: {b[:160].decode('utf-8', 'replace')}")
        d = json.loads(b)
        keep["now"] = d
        R.metric("ms.now", ms)
        bad = check_fields(d, NOW_SPEC)
        if not bad:
            bad = [f"no 'site.{k}'" for k in SITE_SPEC if k not in d["site"]]
        if bad:
            return fail("Missing or wrong fields: " + ", ".join(bad))
        return ok(f"200 in {ms:.0f} ms with the site description the pages need.")
    R.test(L, "api.now", "/api/now answers with the site description", now)

    for path in page_api_paths():
        if path in ("/api/now", "/api/stream") or path.startswith("/api/health/"):
            continue

        def t(path=path):
            q = path + ("?range=24h" if "?" not in path else "")
            st, hd, b, ms = http(q, timeout=60)
            if st in (405, 501):
                return skip("A write-only address.")
            if st != 200:
                return fail(f"Answered {st}: {b[:160].decode('utf-8', 'replace')}")
            if "json" not in hd.get("Content-Type", ""):
                return fail(f"Answered with {hd.get('Content-Type')} instead of JSON.")
            d = json.loads(b)
            keep[path] = d
            name = path[5:].replace("/", "_")
            R.metric(f"ms.{name}", ms)
            if isinstance(d, dict):
                for k, v in d.items():
                    if isinstance(v, list):
                        R.metric(f"n.{name}.{k}", len(v))
            return warn(f"Correct, but took {ms:.0f} ms.") if ms > SLOW_MS else ok(f"200 JSON in {ms:.0f} ms, {len(b) / 1024:.0f} KB.")
        R.test(L, f"api.{path[5:]}", f"{path} answers", t)

    def stream():
        s = socket.create_connection(("127.0.0.1", PORT), timeout=15)
        try:
            s.sendall(f"GET /api/stream HTTP/1.1\r\nHost: {HOST}\r\nAccept: text/event-stream\r\n\r\n".encode())
            buf, t0 = b"", time.time()
            while b"\n\n" not in buf.split(b"\r\n\r\n", 1)[-1] and time.time() - t0 < 15:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        finally:
            s.close()
        head, _, body = buf.partition(b"\r\n\r\n")
        if b" 404 " in head.split(b"\r\n")[0]:
            return skip("This collector has no live stream.")
        if b" 200 " not in head.split(b"\r\n")[0]:
            return fail(f"Live stream answered: {head[:80]!r}")
        line = next((l for l in body.split(b"\n") if l.startswith(b"data: ")), None)
        if not line:
            return fail("The live stream sent nothing within 15 s.")
        json.loads(line[6:])
        return ok(f"The live stream sent an update in {time.time() - t0:.1f} s.")
    R.test(L, "api.stream", "The live stream sends updates", stream)

    def statics():
        html, _ = page_scripts()
        if not html:
            return skip("No web/index.html in this tree.")
        refs = [r for r in re.findall(r'(?:src|href)="([^"#:]+?)(?:\?v=([\w.]+))?"', html) if not r[0].startswith("/api")]
        vers = {v for _, v in refs if v}
        bad = [] if len(vers) <= 1 else [f"the page asks for {len(vers)} different versions: {sorted(vers)}"]
        for f, v in refs:
            p = os.path.join(APP, "web", f.lstrip("/"))
            st, hd, b, _ = http("/" + f.lstrip("/") + (f"?v={v}" if v else ""))
            if st != 200:
                bad.append(f"{f} answered {st}")
            elif hashlib.sha256(b).hexdigest() != sha(p):
                bad.append(f"{f} served differs from the file on disk")
        return fail("; ".join(bad)) if bad else ok(f"{len(refs)} page files served, identical to disk.")
    R.test(L, "static.files", "The page's files are served and match the disk", statics)

    def views():
        html, js = page_scripts()
        menu = set(re.findall(r'data-view="([a-z]+)"', html))
        have = set(re.findall(r"VIEWS\.([a-z]+)\s*=", js)) | set(re.findall(r"^\s+([a-z]+)\s*:\s*(?:async\s*)?(?:\(|function|main\s*=>)", js, re.M))
        if not menu:
            return skip("The menu has no data-view entries.")
        missing = sorted(menu - have)
        return fail("The menu offers pages that do not exist: " + ", ".join(missing)) if missing \
            else ok(f"All {len(menu)} menu entries have a page.")
    R.test(L, "static.views", "Every menu entry has a page", views)


# ---------------------------------------------------------------- locks (deterministic refusals)


def own_addresses():
    """This machine's non-loopback IPv4 addresses."""
    out = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))                          # no packet is sent; this picks the outgoing address
        out.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for a in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            out.add(a[4][0])
    except OSError:
        pass
    return sorted(a for a in out if not a.startswith("127."))


def allowed(addr):
    for n in COL.get("allow", []):
        try:
            if ipaddress.ip_address(addr) in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def layer_locks(R):
    L = "locks"

    def host_hdr():
        st, _, b, _ = http("/api/now", host=f"attacker.example:{PORT}")
        return ok("A request naming a foreign host gets 403.") if st == 403 else fail(f"A request naming a foreign host got {st}.")
    R.test(L, "sec.host", "Requests for a foreign host name are refused (DNS rebinding)", host_hdr, urgent=True)

    def stranger():
        cands = [a for a in own_addresses() if not allowed(a)]
        if not cands:
            return skip("Every address of this machine is on the allow list, so no stranger can be imitated from here.")
        tried = []
        for addr in cands:
            try:
                st = raw_http(addr, f"GET /api/now HTTP/1.0\r\nHost: {addr}:{PORT}\r\n\r\n", timeout=5)
            except OSError:
                tried.append(f"{addr}: not listening")
                continue
            tried.append(f"{addr}: {st}")
            if st != 403:
                return fail(f"A caller not on the allow list got {st} (via {addr}).")
        return ok("A caller not on the allow list is refused (" + ", ".join(tried) + ").")
    R.test(L, "sec.allowlist", "Callers not on the allow list are refused", stranger, urgent=True)

    def forged():
        path = ST.get("write_probe", "/api/navorder")
        a = http(path, method="POST", headers={"Content-Type": "application/json"}, body=b"{}")[0]
        if a == 404:
            return skip(f"{path} does not exist; set selftest.write_probe to a write address.")
        b = http(path, method="POST", headers={"Content-Type": "application/json", "X-Netmon": "1",
                                               "Origin": "http://attacker.example"}, body=b"{}")[0]
        c = raw_http("127.0.0.1", f"POST {path} HTTP/1.0\r\nHost: {HOST}\r\nX-Netmon: 1\r\nContent-Length: 20000\r\n\r\n")
        bad = [f"{n} got {s}, expected {e}" for n, s, e in (("a write without the netmon header", a, 403),
                                                             ("a write from a foreign page", b, 403),
                                                             ("an oversized write", c, 400)) if s != e]
        return fail("; ".join(bad)) if bad else ok("Writes without the header, from a foreign page, or oversized are all refused.")
    R.test(L, "sec.writes", "Forged and oversized writes are refused", forged, urgent=True)

    def traversal():
        bad = []
        for p in ("/../config.json", "/%2e%2e/config.json", "/..%2fconfig.json", "/web/../../config.json", "/../netmon.py"):
            st, _, b, _ = http(p)
            if st == 200 or b"health_machines" in b or b"token" in b:
                bad.append(f"{p} answered {st}")
        return fail("; ".join(bad)) if bad else ok("Five path tricks aimed at the settings file all fail.")
    R.test(L, "sec.paths", "Path tricks cannot read files outside the web folder", traversal, urgent=True)

    def health_push():
        a = http("/api/health/report", method="POST", headers={"X-Health-Machine": "nosuch", "X-Health-Token": "x"}, body=b"v|1|1\n")[0]
        if a == 404:
            return skip("This collector takes no pushed health reports.")
        return ok("A forged health report is refused.") if a == 403 else fail(f"A report for an unknown machine got {a}.")
    R.test(L, "sec.health", "Forged machine health reports are refused", health_push, urgent=True)

    def gate_refuses():
        if not router_set():
            return skip("No router configured.")
        rc, out = gate("cat /etc/shadow")
        rc2, out2 = gate("vpn statusX")
        bad = [f"'{c}' gave exit {r}: {o.strip()[:60]}" for c, r, o in (("cat /etc/shadow", rc, out), ("vpn statusX", rc2, out2))
               if r == 0 or "not-allowed" not in o]
        return fail("; ".join(bad)) if bad else ok("The router's netmon key refuses commands outside its list.")
    R.test(L, "sec.gate", "The router refuses commands netmon's key is not allowed", gate_refuses, urgent=True)


# ---------------------------------------------------------------- router (deterministic: equals what was blessed)


def integrity():
    rows = gate_lines("integrity")
    d = {"files": {}, "sqm": {}, "qdisc": {}, "ctinfo": {}, "mangle": {}}
    for r in rows:
        k = r[0]
        if k == "v": d["ts"] = int(r[2])
        elif k == "file": d["files"][r[1]] = {"sha": r[2], "kept": r[3] == "1"}
        elif k == "sqm": d["sqm"][r[1]] = r[2:8]
        elif k == "qdisc": d["qdisc"][r[1]] = {"bw": unit(r[2]) if r[2] else None, "mode": r[3]}
        elif k == "ctinfo": d["ctinfo"][r[1]] = int(r[2] or 0)
        elif k == "mangle": d["mangle"][r[1]] = (int(r[2] or 0), int(r[3] or 0))
        elif k == "prio_pkts": d["prio_pkts"] = int(r[1] or 0)
        elif k == "l2block": d["l2block"] = int(r[1] or 0)
        elif k == "natdns": d["natdns"] = int(r[1] or 0)
        elif k == "cron": d["cron"] = int(r[2] or 0)
        elif k == "vpndns": d["vpndns"] = json.loads("|".join(r[1:]) or "null")
    return d


def vpn_status():
    rc, out = gate("vpn status")
    return json.loads(out) if rc == 0 else {}


def layer_router(R, I, M):
    L = "router"
    if not router_set():
        R.add(L, "router.gate", "The router answers the self-test", "SKIP", "No router configured (router.ip or router.ssh).")
        return
    if I is None:
        R.add(L, "router.gate", "The router answers the self-test", "FAIL", "The router gate did not answer the integrity request.", urgent=True)
        return
    blessed = (M or {}).get("router", {})
    try:
        g = vpn_status()
        vpn_on = g.get("enabled") == "1" and g.get("rule") == "1"
    except Exception:
        vpn_on = True                                        # unknown counts as on: the stricter check

    def files():
        bad, gone = [], []
        for f, v in I["files"].items():
            if v["sha"] == "missing":
                gone.append(f)
            elif blessed.get("files", {}).get(f) and v["sha"] != blessed["files"][f]:
                bad.append(f)
        if gone:
            return fail("Missing on the router: " + ", ".join(gone))
        if bad:
            return fail("Changed since they were blessed: " + ", ".join(bad) + ". After a deliberate change run: selftest.py bless")
        return ok(f"All {len(I['files'])} netmon files on the router are exactly as blessed.") if blessed.get("files") else skip("No blessed copy yet. Run: selftest.py bless")
    R.test(L, "router.files", "The router's netmon files are unchanged", files, urgent=True)

    def kept():
        lost = [f for f, v in I["files"].items() if not v["kept"] and v["sha"] != "missing"]
        return warn("Not kept on a firmware upgrade: " + ", ".join(lost) + ". Add them to /etc/sysupgrade.conf.") if lost \
            else ok("Every netmon file on the router survives a firmware upgrade.")
    R.test(L, "router.kept", "The router's netmon files survive a firmware upgrade", kept)

    def sqm():
        want = blessed.get("sqm")
        if not I["sqm"] and not want:
            return skip("No SQM shaper is configured on the router.")
        if not want:
            return skip("No blessed copy yet. Run: selftest.py bless")
        bad = [f"{k}: {I['sqm'].get(k)} instead of {v}" for k, v in want.items() if I["sqm"].get(k) != v]
        return fail("; ".join(bad)) if bad else ok("Every SQM shaper section is as blessed: " +
                                                   ", ".join(f"{v[0]} {v[2]} down / {v[3]} up kbit/s" for v in want.values()))
    R.test(L, "router.sqm", "The bufferbloat shaper settings are as blessed", sqm)

    def shapers():
        if not I["sqm"]:
            return skip("No SQM shaper is configured on the router.")
        bad, n = [], 0
        vpn_if = CFG.get("vpn", {}).get("interface")
        for sec, s in I["sqm"].items():
            dev = s[0]
            if s[1] != "1" or (dev == vpn_if and not vpn_on):
                continue
            for d, want in ((dev, float(s[3] or 0) * 1e3), ("ifb4" + dev, float(s[2] or 0) * 1e3)):
                q = I["qdisc"].get(d)
                if q is None:
                    continue                                 # not in the gate's SHAPER_DEVS list
                n += 1
                if q.get("bw") != want:
                    bad.append(f"{d} runs at {q.get('bw')} bit/s, set to {want:.0f}")
        if bad:
            return fail("; ".join(bad) + ". The shaper did not apply its settings.")
        return ok(f"{n} shapers run at exactly their set speeds.") if n else skip("No shaper device is in the gate's SHAPER_DEVS list.")
    R.test(L, "router.shapers", "The shapers actually run at the set speeds", shapers)

    def prio():
        want = blessed.get("mangle") or {}
        if not want or not any(v[0] for v in want.values()):
            return skip("No traffic priority rules were blessed.")
        bad = [f"{k} has {I['mangle'].get(k)} (rules, hooks), blessed {tuple(v)}" for k, v in want.items() if tuple(I["mangle"].get(k, ())) != tuple(v)]
        return fail("; ".join(bad)) if bad else ok("The traffic priority rules are in place.")
    R.test(L, "router.prio", "The traffic priority rules are in place", prio)

    def l2block():
        want = blessed.get("l2block", 0)
        if not want:
            return skip("No layer 2 block was blessed.")
        have = I.get("l2block", 0)
        return ok(f"All {have} bridge drop rules are in force.") if have >= want else fail(f"{have} of {want} bridge drop rules are in force.")
    R.test(L, "router.l2block", "The layer 2 block is in force", l2block, urgent=True)

    def clock():
        diff = I["ts"] - time.time()
        return ok(f"The router's clock is {abs(diff):.0f} s from the collector's.") if abs(diff) < 10 else warn(f"The router's clock is {diff:+.0f} s from the collector's.")
    R.test(L, "router.clock", "The router's clock agrees with the collector", clock)

    def contract():
        bad = []
        for cmd, fn in (("vitals", check_vitals), ("vpn status", check_vpn_status), ("leases", check_leases)):
            rc, out = gate(cmd)
            if rc != 0:
                bad.append(f"'{cmd}' exit {rc}: {out.strip()[:60]}")
                continue
            bad += [f"{cmd}: {b}" for b in fn(out)]
        for cmd, kinds in (("links", LINKS_KINDS), ("health", HEALTH_KINDS)):
            rc, out = gate(cmd, timeout=60)
            if rc != 0:
                bad.append(f"'{cmd}' exit {rc}: {out.strip()[:60]}")
                continue
            bad += [f"{cmd}: {b}" for b in check_lines(out, kinds)[0]]
        return fail("; ".join(bad[:8])) if bad else ok("vitals, vpn status, leases, links and health all follow the gate contract.")
    R.test(L, "router.contract", "The router's answers follow the gate contract", contract)


# ---------------------------------------------------------------- VPN and DNS (deterministic cross-checks)


def dns_query(server, name, timeout=3):
    """Ask server for name's A record over UDP. Returns a list of addresses, [] for no answer, None on timeout."""
    qid = random.randint(0, 65535)
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.strip(".").split(".")) + b"\x00" + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (server, 53))
        r, _ = s.recvfrom(4096)
    except OSError:
        return None
    finally:
        s.close()
    an = struct.unpack("!H", r[6:8])[0]
    i = len(q)
    out = []
    for _ in range(an):
        while i < len(r) and r[i] and r[i] < 0xC0:
            i += r[i] + 1
        i += 2 if i < len(r) and r[i] >= 0xC0 else 1
        t, _c, _ttl, ln = struct.unpack("!HHIH", r[i:i + 10])
        i += 10
        if t == 1 and ln == 4:
            out.append(socket.inet_ntoa(r[i:i + 4]))
        i += ln
    return out


def public_ip():
    req = urllib.request.Request("https://www.cloudflare.com/cdn-cgi/trace", headers={"User-Agent": "netmon-selftest"})
    text = urllib.request.urlopen(req, timeout=8).read().decode()
    return dict(l.split("=", 1) for l in text.splitlines() if "=" in l).get("ip")


def warming(keep):
    """The collector's live state is empty for its first minutes after a restart."""
    up = time.time() - ((keep.get("/api/selftest") or {}).get("started") or 0)
    return f"The collector restarted {int(up)} s ago; its live data needs 3 minutes." if up < 180 else None


def layer_vpn(R, I, keep):
    L = "vpn"
    if not VPN_ON_CFG:
        return
    try:
        g = vpn_status()
    except Exception as e:
        R.add(L, "vpn.gate", "The router reports the VPN state", "FAIL", f"No answer: {e}")
        return
    on = g.get("enabled") == "1" and g.get("rule") == "1"

    def handshake():
        if not on:
            return skip("The VPN is off.")
        age = g["now"] - g.get("handshake", 0)
        return ok(f"Last WireGuard handshake {age} s ago.") if age < 180 else (warn if age < 300 else fail)(f"Last WireGuard handshake {age} s ago: the tunnel may be down.")
    R.test(L, "vpn.up", "The tunnel is alive", handshake, urgent=True)

    def exit_ip():
        cidrs = ST.get("direct_exit_cidrs") or []
        if not cidrs:
            return skip("Set selftest.direct_exit_cidrs to the ISP's address ranges to check for leaks.")
        ip = public_ip()
        if not ip:
            return warn("Could not learn this network's public address.")
        direct = any(ipaddress.ip_address(ip) in ipaddress.ip_network(c, strict=False) for c in cidrs)
        if on and direct:
            return fail(f"LEAK: the VPN is on but the internet sees this network as {ip}, an ISP address.")
        if not on and not direct:
            return warn(f"The VPN is off but the internet sees {ip}, which is not in the ISP's ranges.")
        return ok(f"The internet sees {ip}: {'the VPN' if on else 'the ISP, as expected with the VPN off'}.")
    R.test(L, "vpn.exit", "The internet sees the address it should (no leak)", exit_ip, urgent=True)

    def dns():
        d = (I or {}).get("vpndns") or g.get("dns") or {}
        want = "tunnel" if on else "direct"
        bad = []
        if d.get("want") != want:
            bad.append(f"DNS wants '{d.get('want')}' while the VPN is {'on' if on else 'off'}")
        if d.get("have") != d.get("want") or not d.get("ok"):
            bad.append(f"DNS is '{d.get('have')}' but should be '{d.get('want')}'")
        return fail("; ".join(bad)) if bad else ok(f"DNS goes {'through the tunnel' if on else 'direct'}, matching the VPN.")
    R.test(L, "vpn.dns", "DNS follows the VPN", dns, urgent=True)

    def egress():
        c = ndb()
        if not has_table(c, "tunnel_min"):
            return skip("The collector keeps no tunnel records.")
        r = c.execute("SELECT ts, vpn_on, n_tunnel, n_direct FROM tunnel_min ORDER BY ts DESC LIMIT 1").fetchone()
        if not r:
            return skip("No tunnel records yet.")
        ts, von, nt, nd = r
        if not on:
            return ok(f"VPN off: {nd} connections go direct, as expected.")
        if nd == 0:
            return ok(f"All {nt} internet connections use the tunnel (at {hm(ts)}).")
        return (fail if nd > 5 and nd > 0.1 * nt else warn)(f"{nd} connections bypass the tunnel while {nt} use it (at {hm(ts)}).")
    R.test(L, "vpn.egress", "No connection bypasses the tunnel", egress, urgent=True)


def layer_dns(R):
    p = ST.get("dns_probe") or {}
    server = p.get("server") or CFG.get("dns", {}).get("server") or ROUTER.get("ip")
    if not server:
        return

    def resolve():
        bad = []
        name = p.get("allowed", "example.com")
        a = dns_query(server, name)
        if not a:
            bad.append(f"{server} gave no answer for {name}")
        if p.get("blocked"):
            b = dns_query(server, p["blocked"])
            if b not in ([], ["0.0.0.0"]):
                bad.append(f"{p['blocked']} was answered ({b}) but should be blocked")
        what = "answers normal names" + (" and blocks a listed name" if p.get("blocked") else "")
        return fail("; ".join(bad)) if bad else ok(f"The DNS server {server} {what}.")
    R.test("vpn", "dns.resolve", "The DNS filter answers" + (" and blocks" if p.get("blocked") else ""), resolve)


# ---------------------------------------------------------------- freshness (deterministic limits)


DEFAULT_TABLES = [["app_15s", "ts", 15, "traffic per device"], ["vitals_min", "ts", 60, "router vitals"],
                  ["latency_min", "ts", 60, "round-trip times"], ["link_min", "ts", 60, "wired and Wi-Fi links"],
                  ["dns", "ts", 60, "DNS lookups"], ["conn", "last", 30, "connection table"]]


def layer_fresh(R, keep):
    L = "fresh"
    if not os.path.exists(DBPATH_NETMON):
        R.add(L, "fresh.db", "The collector's database exists", "FAIL", f"No database at {DBPATH_NETMON} (set selftest.db).")
        return
    c = ndb()
    now = time.time()
    tables = ST.get("fresh_tables") or DEFAULT_TABLES
    if VPN_ON_CFG and not ST.get("fresh_tables"):
        tables = tables + [["tunnel_min", "ts", 60, "tunnel records"]]
    for t, col, every, title in tables:
        def f(t=t, col=col, every=every):
            if not has_table(c, t):
                return skip(f"The collector has no table {t}.")
            last = c.execute(f"SELECT max({col}) FROM {t}").fetchone()[0]
            if not last:
                return fail("Nothing recorded.")
            age = now - last
            R.metric(f"age.{t}", age)
            lim_w, lim_f = max(300, every * 5), max(900, every * 15)
            return (ok if age < lim_w else warn if age < lim_f else fail)(f"Newest record {ago(age)} old (warning after {ago(lim_w)}, failure after {ago(lim_f)}).")
        R.test(L, f"fresh.{t}", f"Still recording {title}", f)

    def machines():
        h = keep.get("/api/health") or {}
        if not h.get("machines"):
            return skip("No machines report health.")
        good, late, dead, waiting = [], [], [], []
        for m in h["machines"]:
            mid, ts = m.get("id"), m.get("ts")
            if not ts:
                (waiting if m.get("on_demand") else dead).append(str(mid))
                continue
            age = now - ts
            if age < 900:
                good.append(str(mid))
            elif m.get("on_demand"):
                waiting.append(f"{mid} (off, last seen {ago(age)} ago)")
            else:
                (late if age < 3600 else dead).append(f"{mid} {ago(age)} ago")
        extra = f" Not reporting: {', '.join(waiting)}." if waiting else ""
        if dead:
            return fail("No recent report: " + ", ".join(dead) + "." + extra)
        if late:
            return warn("Late: " + ", ".join(late) + "." + extra)
        return ok(f"Reporting on time: {', '.join(good)}.{extra}")
    R.test(L, "fresh.machines", "Every machine's health report is recent", machines)

    def threads():
        d = keep.get("/api/selftest") or {}
        have, want = set(d.get("threads") or []), set(d.get("threads_expected") or [])
        if not have or not want:
            return skip("The collector does not list its expected and running threads.")
        gone = sorted(want - have)
        return fail("Stopped inside the collector: " + ", ".join(gone)) if gone else ok(f"All {len(want)} of the collector's threads are alive.")
    R.test(L, "fresh.threads", "All of the collector's loops are alive", threads)


# ---------------------------------------------------------------- pages (real browser, macOS)


def layer_pages(R, width=1440, height=900, tag=""):
    L = "pages"
    html, _ = page_scripts()
    views = re.findall(r'data-view="([a-z]+)"', html)
    if not views:
        R.add(L, "ui.views", "The pages open in a browser", "SKIP", "The menu has no data-view entries.")
        return
    if sys.platform != "darwin" or not os.path.exists("/usr/bin/swiftc"):
        R.add(L, "ui.browser", "The pages open in a browser", "SKIP", "The browser check needs macOS with the Swift compiler.")
        return
    exe = os.path.join(DATA, "webcheck")
    src = os.path.join(HERE, "webcheck.swift")
    if not os.path.exists(exe) or os.path.getmtime(src) > os.path.getmtime(exe):
        p = subprocess.run(["/usr/bin/swiftc", "-O", "-o", exe, src], capture_output=True, text=True, timeout=600)
        if p.returncode:
            R.add(L, "ui.build", "The browser checker builds", "FAIL", p.stderr[-400:])
            return
    p = subprocess.run([exe, BASE + "/", ",".join(views), str(width), str(height), ST.get("page_container", "#view")],
                       capture_output=True, text=True, timeout=900)
    got = {}
    for line in p.stdout.splitlines():
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if "view" in o:
            got[o["view"]] = o
    names = dict(re.findall(r'data-view="([a-z]+)"[^>]*>(?:<svg.*?</svg>)?([^<]+)<', html))
    for v in views:
        o = got.get(v)
        title = f"{names.get(v, v).strip()} page works" + (f" at {width} px wide" if tag else "")

        def t(o=o, v=v):
            if o is None:
                return fail(f"The browser never reported on this page. {p.stderr.strip()[-200:]}")
            if o.get("load_error") or o.get("audit_error"):
                return fail(o.get("load_error") or o.get("audit_error"))
            if not tag:
                for k in ("text_len", "marks", "rows", "svg_text"):
                    R.metric(f"ui.{v}.{k}", o.get(k))
            bad, soft = [], []
            if o.get("errors"): bad.append("script errors: " + " | ".join(o["errors"][:3]))
            if o.get("bad"): bad.append("failed requests: " + ", ".join(o["bad"][:3]))
            if not o.get("h1"): bad.append("no page heading")
            if o.get("text_len", 0) < 40 and not o.get("canvas"): bad.append(f"almost empty ({o.get('text_len')} characters)")
            if o.get("canvas") and o.get("ink") == 0: bad.append("the drawing is blank")
            if o.get("junk"): bad.append("shows " + ", ".join(o["junk"]))
            if o.get("blocked"): soft.append(f"tried to change something just by opening ({o['blocked']} writes blocked)")
            if o.get("tiny"): soft.append(f"{o['tiny']} pieces of text under 11.5 px, e.g. {', '.join(o.get('tiny_ex', [])[:2])}")
            if o.get("clipped"): soft.append(f"{o['clipped']} cut-off text, e.g. {', '.join(o.get('clip_ex', [])[:2])}")
            if o.get("page_overflow", 0) > 2: soft.append(f"the page is {o['page_overflow']} px wider than the window")
            if bad and tag:
                return warn("; ".join(bad + soft))
            if bad:
                return fail("; ".join(bad + soft))
            if soft:
                return warn("; ".join(soft))
            return ok(f"Opened in {o.get('secs')} s: {o.get('text_len')} characters, {o.get('marks')} chart marks, {o.get('rows')} rows, no errors.")
        R.test(L, f"ui{tag}.{v}", title, t)


# ---------------------------------------------------------------- plausibility (heuristic)


def history(k, n=96):
    try:
        c = sqlite3.connect(DBPATH, timeout=10)
        return [r[0] for r in c.execute("SELECT v FROM metrics WHERE k=? ORDER BY ts DESC LIMIT ?", (k, n))]
    except sqlite3.Error:
        return []


def latency_floor(name, addr):
    f = (ST.get("latency_floor_ms") or {}).get(name)
    if f:
        return f
    try:
        return 15 if ipaddress.ip_address(addr).is_private else 80
    except ValueError:
        return 80


def layer_sense(R, keep):
    L = "sense"
    H = "heuristic"
    if not os.path.exists(DBPATH_NETMON):
        return
    c = ndb()
    now = int(time.time())

    def latency():
        if not has_table(c, "latency_min"):
            return skip("The collector keeps no latency records.")
        targets = CFG.get("latency_targets") or {}
        if not targets:
            return skip("No latency targets are configured.")
        bad, good = [], []
        for t, addr in targets.items():
            last = [r for r in c.execute("SELECT rtt_med, loss FROM latency_min WHERE target=? AND ts>?", (t, now - 900)) if r[0] is not None]
            week = sorted(r[0] for r in c.execute("SELECT rtt_med FROM latency_min WHERE target=? AND ts>? AND rtt_med IS NOT NULL", (t, now - 7 * 86400)))
            if not last:
                bad.append(f"{t}: no replies in 15 min")
                continue
            med = statistics.median(r[0] for r in last)
            loss = statistics.mean(r[1] or 0 for r in last)
            p95 = week[int(len(week) * .95)] if len(week) > 50 else None
            R.metric(f"lat.{t}", med)
            floor = latency_floor(t, addr)
            lim = max(floor, 1.5 * p95) if p95 else floor * 2
            if med > lim:
                bad.append(f"{t} {med:.0f} ms (normal here: under {lim:.0f})")
            elif loss > 15:
                bad.append(f"{t} loses {loss:.0f}% of pings")
            else:
                good.append(f"{t} {med:.0f} ms")
        return warn("; ".join(bad)) if bad else ok("Last 15 min: " + ", ".join(good) + ", all within this network's normal range.")
    R.test(L, "sense.latency", "Round-trip times are normal for this network", latency, H)

    def traffic():
        if not has_table(c, "app_min"):
            return skip("The collector keeps no per-minute traffic records.")
        r = c.execute("SELECT count(DISTINCT mac), coalesce(sum(down + up), 0) FROM app_min WHERE ts > ?", (now - 900,)).fetchone()
        q = c.execute("SELECT count(*) FROM dns WHERE ts > ?", (now - 900,)).fetchone()[0] if has_table(c, "dns") else None
        R.metric("traffic.devices", r[0]); R.metric("traffic.bytes", r[1]); R.metric("traffic.dns", q)
        if r[0] == 0 or r[1] == 0:
            return fail("No device moved any data in 15 minutes: a collector is broken.")
        if q == 0:
            return fail("No DNS lookup recorded in 15 minutes: the DNS source is broken.")
        return ok(f"Last 15 min: {r[0]} devices moved {r[1] / 1e6:.0f} MB" + (f" and made {q} DNS lookups." if q is not None else "."))
    R.test(L, "sense.traffic", "Traffic and DNS lookups are being recorded", traffic, H)

    def bloat():
        if not has_table(c, "bloat_test"):
            return skip("The collector keeps no bufferbloat tests.")
        r = c.execute("SELECT ts, result FROM bloat_test ORDER BY ts DESC LIMIT 1").fetchone()
        if not r:
            return skip("No bufferbloat test yet.")
        d = json.loads(r[1])
        g = d.get("grade")
        msg = f"Last test {ago(now - r[0])} ago: grade {g}, {d.get('added_ms', 0):.0f} ms added under load."
        return ok(msg) if g in ("A+", "A", "B") else warn(msg)
    R.test(L, "sense.bloat", "Bufferbloat is under control", bloat, H)

    def logs():
        p = os.path.join(DATA_ROOT, "logs", "netmon.log")
        if not os.path.exists(p):
            return skip(f"No log at {p}.")
        since = max(now - 1800, (keep.get("/api/selftest") or {}).get("started") or 0)   # errors before the last restart are history
        cut = datetime.datetime.fromtimestamp(since).strftime("%Y-%m-%d %H:%M:%S")
        errs, code = [], []
        with open(p, encoding="utf-8", errors="replace") as f:
            f.seek(max(0, os.path.getsize(p) - 2_000_000))
            for line in f:
                if line[:19] < cut or not re.match(r"\d{4}-", line):
                    continue
                if " ERROR " in line or " CRITICAL " in line:
                    errs.append(line[20:].strip()[:140])
                if re.search(r"is not defined|has no attribute|Error:|Traceback|unexpected keyword|object is not", line):
                    code.append(line[20:].strip()[:140])
        R.metric("log.errors", len(errs) + len(code))
        if code:
            return fail(f"{len(code)} programming errors since {hm(since)}, e.g. {code[-1]}")
        return warn(f"{len(errs)} errors since {hm(since)}, e.g. {errs[-1]}") if errs else ok(f"No errors in the collector's log since {hm(since)}.")
    R.test(L, "sense.logs", "The collector's log is free of errors", logs, H)

    def storage():
        st = os.statvfs(DATA_ROOT)
        free = st.f_bavail / st.f_blocks
        size = sum(os.path.getsize(p) for p in (DBPATH_NETMON, DBPATH_NETMON + "-wal") if os.path.exists(p)) / 1e9
        cap = ST.get("db_cap_gb")
        R.metric("db.gb", size)
        bad = []
        if free < .10: bad.append(f"only {free:.0%} of the data disk is free")
        if cap and size > .9 * cap: bad.append(f"the database is {size:.1f} of its {cap} GB limit")
        return warn("; ".join(bad)) if bad else ok(f"Data disk {free:.0%} free; database {size * 1000:.0f} MB.")
    R.test(L, "sense.storage", "There is room to keep recording", storage, H)

    def flapping():
        if not has_table(c, "event"):
            return skip("The collector keeps no event records.")
        rows = c.execute("SELECT subject, count(*) FROM event WHERE kind='check' AND ts > ? GROUP BY subject HAVING count(*) >= 8", (now - 3600,)).fetchall()
        return warn("Changing state again and again in the last hour: " + ", ".join(f"{s} ({n} times)" for s, n in rows)) if rows \
            else ok("No check is flipping between states.")
    R.test(L, "sense.flapping", "No check keeps flipping on and off", flapping, H)

    def baseline():
        """Every number the run recorded, against its own last 24 hours: a collapse or a spike is suspicious."""
        odd, n_known, n_learning = [], 0, 0
        for k, v in sorted(R.metrics.items()):
            if k.startswith(("age.", "lat.")):
                continue
            h = history(k)
            if len(h) < 24:
                n_learning += 1
                continue
            n_known += 1
            med = statistics.median(h)
            if k.startswith("ms."):
                if v > 5 * med and v > 1500:
                    odd.append(f"{k[3:]} took {v:.0f} ms (usually {med:.0f})")
            elif med >= 5 and v < 0.2 * med:
                odd.append(f"{k} fell to {v:.0f} (usually {med:.0f})")
            elif med >= 5 and v > 8 * med and k != "log.errors":
                odd.append(f"{k} jumped to {v:.0f} (usually {med:.0f})")
        if not n_known:
            return skip(f"Still learning what is normal: needs 24 runs (6 hours) of history for {n_learning} numbers.")
        return warn("Unusual against the last 24 hours: " + "; ".join(odd[:8])) if odd else \
            ok(f"All {n_known} measured numbers are within their normal range for the last 24 hours" + (f" ({n_learning} still learning)." if n_learning else "."))
    R.test(L, "sense.baseline", "Nothing has collapsed or spiked against its own history", baseline, H)


# ---------------------------------------------------------------- manifest (bless)


def local_hashes():
    return {f: sha(os.path.join(APP, f)) for f in repo_files()}


def bless():
    m = {"ts": int(time.time()), "local": local_hashes(), "router": {}}
    if router_set():
        I = integrity()
        m["router"] = {"files": {f: v["sha"] for f, v in I["files"].items()}, "sqm": I["sqm"],
                       "mangle": {k: list(v) for k, v in I["mangle"].items()}, "l2block": I.get("l2block", 0)}
    os.makedirs(DATA, exist_ok=True)
    tmp = MANIFEST + ".tmp"
    with open(tmp, "w") as f:
        json.dump(m, f, indent=1)
    os.replace(tmp, MANIFEST)
    print(f"Blessed {len(m['local'])} local files and {len(m['router'].get('files', {}))} router files at {hm(m['ts'])}.")


def layer_drift(R, M):
    def t():
        if not M:
            return skip("Nothing blessed yet. Run: selftest.py bless")
        now = local_hashes()
        ch = [f for f, h in now.items() if M["local"].get(f) and h != M["local"][f]]
        new = [f for f, h in now.items() if h and not M["local"].get(f)]
        if ch or new:
            return warn(f"Changed since the last blessed deploy ({hm(M['ts'])}): " + ", ".join((ch + new)[:12]) + ". After a deliberate deploy run: selftest.py bless")
        return ok(f"All {len(now)} netmon files are exactly as blessed at {hm(M['ts'])}.")
    R.test("code", "code.drift", "netmon's files are the blessed version", t)


# ---------------------------------------------------------------- alerts


def send_mail(subject, body):
    """Send one email through the collector's mail code (netmon/alerts.py), and wait for it.
    Returns True when sent; prints and returns False when no address is configured."""
    to = (CFG.get("alerts", {}).get("email_to") or "").strip()
    if not to:
        print(f"(no alert address configured) {subject}")
        return False
    from netmon import alerts, config
    config.load(CFG["_path"])
    send = getattr(alerts, "send_now", None)
    if send:
        return bool(send(subject, body))
    alerts._send(to, subject, body)
    return True


def queue_changes(changes, R):
    """Append the failures that started or ended in this run to the pending daily summary."""
    if not changes:
        return
    newf = [r for r, old in changes if r["hard"] == "FAIL"]
    fixed = [r for r, old in changes if old == "FAIL" and r["hard"] != "FAIL"]
    with open(DIGEST, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": time.time(), "new": [[r["title"], r["detail"]] for r in newf],
                             "fixed": [r["title"] for r in fixed]}) + "\n")
    print(f"queued for the daily summary: {len(newf)} new, {len(fixed)} fixed")


def send_daily_digest(R):
    """Once a day, at or after selftest.digest_hour local time, email one summary of every change since the last."""
    now = datetime.datetime.now()
    today = now.strftime("%Y-%m-%d")
    last = open(DIGEST_SENT).read().strip() if os.path.exists(DIGEST_SENT) else ""
    if now.hour < int(ST.get("digest_hour", 7)) or last == today or not os.path.exists(DIGEST):
        return
    rows = [json.loads(line) for line in open(DIGEST, encoding="utf-8") if line.strip()]
    if not rows:
        return
    new_lines, fixed_lines = [], []
    for row in rows:
        when = hm(row["ts"])
        new_lines += [f"- {when}: {t}\n  {d}" for t, d in row.get("new", [])]
        fixed_lines += [f"- {when}: {t}" for t in row.get("fixed", [])]
    still = [r for r in R.results if r.get("hard") == "FAIL"]
    parts = []
    if new_lines:
        parts.append("NEW PROBLEMS SINCE THE LAST SUMMARY\n" + "\n".join(new_lines))
    if fixed_lines:
        parts.append("FIXED SINCE THE LAST SUMMARY\n" + "\n".join(fixed_lines))
    parts.append("FAILING RIGHT NOW\n" + ("\n".join(f"- {r['title']}" for r in still) if still else "- nothing"))
    site = CFG.get("site", {}).get("name", "netmon")
    subj = f"Netmon self-test, {site}: daily summary ({len(new_lines)} new, {len(fixed_lines)} fixed, {len(still)} failing now)"
    body = f"Daily summary of the netmon self-test for {site}, which runs every 15 minutes.\n\n" + "\n\n".join(parts)
    try:
        if send_mail(subj, body[:20000]):
            os.replace(DIGEST, DIGEST + "." + today)
            with open(DIGEST_SENT, "w") as f:
                f.write(today)
    except Exception as e:
        print("daily summary failed:", e, file=sys.stderr)


# ---------------------------------------------------------------- precheck (before a deploy)


def precheck(root):
    """Check a candidate tree before it replaces the running one: every .py compiles with no undefined names, and
    the netmon package imports (with the same config.json) without error. Exit status 1 means: do not deploy."""
    root = os.path.abspath(root)
    files = [f for f in glob.glob(os.path.join(root, "netmon", "*.py")) + glob.glob(os.path.join(root, "*.py"))]
    problems = []
    for f in files:
        try:
            miss = undefined_globals(f)
        except SyntaxError as e:
            problems.append(f"{os.path.relpath(f, root)}: syntax error at line {e.lineno}: {e.msg}")
            continue
        if miss:
            problems.append(f"{os.path.relpath(f, root)}: uses names nothing defines: {', '.join(miss[:8])}")
    p = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, sys.argv[1]); import netmon; print('import ok')", root],
                       capture_output=True, text=True, timeout=120, cwd=root,
                       env={**os.environ, "NETMON_CONFIG": CFG["_path"], "PYTHONDONTWRITEBYTECODE": "1"})
    if p.returncode:
        problems.append("import failed: " + " | ".join(p.stderr.strip().splitlines()[-4:]))
    if problems:
        print("PRECHECK FAILED: do not deploy.\n  " + "\n  ".join(problems))
        return 1
    print(f"precheck ok: {len(files)} files, {p.stdout.strip()}")
    return 0


# ---------------------------------------------------------------- run


def main(mode):
    os.makedirs(QUEUE, exist_ok=True)
    lockf = open(os.path.join(DATA, "run.lock"), "w")
    try:
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        for f in os.listdir(QUEUE):
            try:
                os.remove(os.path.join(QUEUE, f))
            except OSError:
                pass
        print("another self-test is running")
        return 0
    queued = os.listdir(QUEUE)
    how = "button" if queued else ("quick" if mode == "quick" else "schedule")
    for f in queued:                                          # the scheduler starts a run while the queue is not empty
        try:
            os.remove(os.path.join(QUEUE, f))
        except OSError:
            pass
    t0 = time.time()
    R = Run()
    keep = {}
    M = None
    try:
        M = json.load(open(MANIFEST))
    except (OSError, ValueError):
        pass
    for p in ("/api/selftest", "/api/health"):               # the collector's own view, read once per run
        try:
            keep[p] = getj(p)
        except Exception:
            pass
    layer_code(R)
    layer_drift(R, M)
    layer_endpoints(R, keep)
    layer_locks(R)
    if mode != "quick":
        I = None
        if router_set():
            try:
                I = integrity()
            except Exception as e:
                print("integrity:", e, file=sys.stderr)
        layer_router(R, I, M)
        layer_vpn(R, I, keep)
        layer_dns(R)
        layer_fresh(R, keep)
        layer_pages(R)
        if int(t0 // 900) % 4 == 0 or how == "button":        # hourly: the pages again at laptop width
            layer_pages(R, 1024, 700, tag="-narrow")
        layer_sense(R, keep)
    # A deploy restarts the collector; pages and endpoints tested across that moment fail for no real reason.
    try:
        started = getj("/api/selftest").get("started")
    except Exception:
        started = None
    before = (keep.get("/api/selftest") or {}).get("started")
    if started and before and started != before:
        for r in R.results:
            if r["status"] == "FAIL" and r["layer"] in ("pages", "endpoints", "fresh"):
                r["status"], r["detail"] = "SKIP", f"The collector restarted during this run (at {hm(started)}); not counted. Was: {r['detail']}"[:600]
    secs = time.time() - t0
    counts = {s: sum(1 for r in R.results if r["status"] == s) for s in ("PASS", "WARN", "FAIL", "SKIP")}
    if mode == "quick":
        for r in R.results:
            if r["status"] != "PASS":
                print(f"{r['status']:4}  {r['title']}\n      {r['detail']}")
        print(f"quick self-test: {counts['PASS']} passed, {counts['WARN']} warnings, {counts['FAIL']} failed, {secs:.0f} s")
        return 1 if counts["FAIL"] else 0

    # state, hard state and history
    now = int(t0)
    db = sqlite3.connect(DBPATH, timeout=30)
    db.executescript(SCHEMA)
    changes = []
    for r in R.results:
        row = db.execute("SELECT status, streak, hard, since FROM state WHERE id=?", (r["id"],)).fetchone()
        streak = (row[1] + 1) if row and row[0] == r["status"] else 1
        old_hard = row[2] if row else None
        need = 1 if r["urgent"] or r["status"] == "PASS" else 2
        hard = r["status"] if streak >= need else (old_hard or "PASS")    # a failure counts once it repeats
        since = row[3] if row and hard == old_hard else now
        r.update(streak=streak, hard=hard, since=since)
        db.execute("INSERT OR REPLACE INTO state VALUES(?,?,?,?,?)", (r["id"], r["status"], streak, hard, since))
        if (hard == "FAIL") != (old_hard == "FAIL") and (old_hard is not None or hard == "FAIL"):
            changes.append((r, old_hard))
    db.execute("INSERT OR REPLACE INTO runs VALUES(?,?,?,?,?,?,?)", (now, round(secs, 1), counts["PASS"], counts["WARN"], counts["FAIL"], counts["SKIP"], how))
    db.executemany("INSERT OR REPLACE INTO results VALUES(?,?,?,?)", [(now, r["id"], r["status"], r["detail"]) for r in R.results])
    db.executemany("INSERT OR REPLACE INTO metrics VALUES(?,?,?)", [(now, k, v) for k, v in R.metrics.items()])
    cut = now - 60 * 86400
    for t in ("runs", "results", "metrics"):
        db.execute(f"DELETE FROM {t} WHERE ts < ?", (cut,))
    db.commit()
    out = {"ts": now, "secs": round(secs, 1), "how": how, "counts": {k.lower(): v for k, v in counts.items()},
           "layers": [{"id": a, "title": b, "about": c} for a, b, c in LAYERS], "results": R.results,
           "blessed": M["ts"] if M else None, "next": now + 900}
    tmp = LATEST + ".tmp"
    with open(tmp, "w") as f:
        json.dump(out, f, separators=(",", ":"))
    os.replace(tmp, LATEST)
    queue_changes(changes, R)
    send_daily_digest(R)
    print(f"{hm(now)} self-test: {counts['PASS']} passed, {counts['WARN']} warnings, {counts['FAIL']} failed, {counts['SKIP']} skipped, {secs:.0f} s"
          + (f"; {len(changes)} changes queued" if changes else ""))
    return 0


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "run"
    if mode == "bless":
        bless()
    elif mode == "precheck" and len(sys.argv) > 2:
        sys.exit(precheck(sys.argv[2]))
    elif mode in ("run", "quick"):
        sys.exit(main(mode))
    else:
        print(__doc__)
        sys.exit(2)
