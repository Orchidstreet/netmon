# SPDX-License-Identifier: AGPL-3.0-or-later
"""Health checks in the Nagios style: each check returns a state and one plain sentence.

Touches: probes from the collector (ping, dig, HTTP GET, TCP connect, TLS handshake, an optional
UPnP IGD status request to the uplink, `tailscale status`); the check_state and event tables;
alerts.py for CRITICAL and recovery mail; heal.py when a check changes hard state.

The check list is config.checks(): CFG["checks"] when present, else a default list built from the
site's names. A check turns hard WARNING or CRITICAL after `attempts` failures in a row (default 3).
"""
import concurrent.futures
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request

from . import alerts, config, db as dbm, heal
from .config import CFG
from .state import LOG, STOP, S, fmt_time

OK, WARN, CRIT, UNKNOWN = 0, 1, 2, 3
STATE_NAME = {OK: "OK", WARN: "WARNING", CRIT: "CRITICAL", UNKNOWN: "UNKNOWN"}


def grade(value, warn, crit, higher_is_worse=True):
    if value is None:
        return UNKNOWN
    if higher_is_worse:
        return CRIT if value >= crit else WARN if value >= warn else OK
    return CRIT if value <= crit else WARN if value <= warn else OK


def ck_ping(c):
    from .collect import ping
    med, loss, lo, hi = ping(c["host"], 3)
    if med is None:
        return CRIT, f"No reply from {c['host']} (3 pings lost)."
    st = max(grade(loss, c.get("loss_warn", 20), c.get("loss_crit", 60)),
             grade(med, c.get("rtt_warn", 100), c.get("rtt_crit", 500)))
    return st, f"Replies in {med:.1f} ms, {loss:.0f}% lost."


def ck_http(c):
    t0 = time.time()
    try:
        req = urllib.request.Request(c["url"], method="GET", headers={"User-Agent": "netmon"})
        with urllib.request.urlopen(req, timeout=c.get("timeout", 8)) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:
        return CRIT, f"Could not load {c['url']}: {e.__class__.__name__}."
    ms = (time.time() - t0) * 1000
    if code >= 400:
        return CRIT, f"{c['url']} answered with error {code}."
    return grade(ms, c.get("ms_warn", 1500), c.get("ms_crit", 5000)), f"{c['url']} loaded in {ms:.0f} ms."


def ck_dns(c):
    q = c.get("query", "example.com")
    try:
        p = subprocess.run([shutil.which("dig") or "dig", "+short", "+time=2", "+tries=1", q, f"@{c['server']}"],
                           capture_output=True, text=True, timeout=6)
        ans = [x for x in p.stdout.split() if re.match(r"^[\d.]+$", x)]
    except Exception:
        ans = []
    if not ans:
        return CRIT, f"{c['server']} gave no answer for {q}."
    if c.get("expect") and c["expect"] not in ans:
        return WARN, f"{c['server']} answered {ans[0]} for {q}, expected {c['expect']}."
    return OK, f"{c['server']} answered {ans[0]} for {q}."


def ck_tcp(c):
    try:
        with socket.create_connection((c["host"], c["port"]), timeout=5):
            return OK, f"Port {c['port']} on {c['host']} is open."
    except Exception:
        return CRIT, f"Port {c['port']} on {c['host']} does not answer."


def ck_tls(c):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((c["host"], c.get("port", 443)), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=c["host"]) as t:
                exp = ssl.cert_time_to_seconds(t.getpeercert()["notAfter"])
    except Exception as e:
        return CRIT, f"Could not check the certificate of {c['host']}: {e.__class__.__name__}."
    days = (exp - time.time()) / 86400
    return grade(days, c.get("days_warn", 14), c.get("days_crit", 3), False), \
        f"Certificate of {c['host']} expires in {days:.0f} days."


def ck_router(c):
    rn = config.router_name()
    v, age = S.vitals, time.time() - S.vitals_ts
    if not v or age > 120:
        return UNKNOWN, f"No readings from {rn} in the last 2 minutes."
    m = c["metric"]
    if m == "cpu":
        val = v.get("cpu_pct")
        return grade(val, c["warn"], c["crit"]), f"CPU {val:.0f}% busy." if val is not None else "CPU not yet measured."
    if m == "temp":
        val = v["temp_mc"] / 1000
        return grade(val, c["warn"], c["crit"]), f"Chip temperature {val:.0f} °C."
    if m == "mem":
        val = v["mem_avail_kb"] / 1024
        return grade(val, c["warn"], c["crit"], False), f"{val:.0f} MB memory free."
    if m == "conntrack":
        val = 100 * v["conntrack"][0] / max(v["conntrack"][1], 1)
        return grade(val, c["warn"], c["crit"]), f"{v['conntrack'][0]} connections tracked ({val:.0f}% of the limit)."
    if m == "netifyd":
        return (OK, f"The traffic classifier is running, using {v['netifyd_rss_kb'] // 1024} MB.") if v.get("netifyd_rss_kb") \
            else (CRIT, f"The traffic classifier is not running on {rn}. Application names will stop.")
    return UNKNOWN, f"Unknown metric {m}."


def ck_feed(c):
    age = time.time() - S.feed_ts if S.feed_ts else None
    if age is None:
        return UNKNOWN, f"No traffic data yet ({S.feed_status})."
    return grade(age, c["warn"], c["crit"]), f"Last traffic data {age:.0f} seconds ago ({S.feed_status})."


def ck_ports(c):
    """Each wired router port with a cable in should run at the best speed both ends offer."""
    if not S.ports:
        return UNKNOWN, f"No port data from {config.router_name()} yet."
    bad = [p for p in S.ports.values() if p["degraded"]]
    up = [p for p in S.ports.values() if p["up"]]
    fmt = lambda v: f"{v / 1000:g} Gbit/s" if v and v >= 1000 else f"{v} Mbit/s"
    if bad:
        return WARN, "; ".join(f"{p['name']} runs at {fmt(p['speed'])} but both ends can do {fmt(p['best'])}. "
                               "Check the cable." for p in bad)
    return OK, "All connected ports at full speed: " + ", ".join(f"{p['name']} {fmt(p['speed'])}" for p in up) + "."


def ck_disk(c):
    u = shutil.disk_usage(c.get("path") or config.data_dir())
    free = 100 * u.free / u.total
    return grade(free, c["warn_free_pct"], c["crit_free_pct"], False), \
        f"{u.free / 1e9:.0f} GB free on {c.get('path') or config.data_dir()} ({free:.0f}%)."


def ck_dbsize(c):
    size = dbm.db_bytes() / 1e9
    cap = config.retention()[2]
    return grade(100 * size / cap, 80, 95), f"Traffic log is {size:.2f} GB of the {cap} GB limit."


def ck_igd(c):
    """The uplink's internet link state over UPnP IGD (WANIPConnection GetStatusInfo) at c["url"]."""
    svc = c.get("service", "urn:schemas-upnp-org:service:WANIPConnection:1")
    body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:GetStatusInfo xmlns:u="{svc}"/></s:Body></s:Envelope>')
    req = urllib.request.Request(c["url"], data=body.encode(),
                                 headers={"Content-Type": 'text/xml; charset="utf-8"', "SoapAction": f"{svc}#GetStatusInfo"})
    un = config.uplink_name()
    try:
        x = urllib.request.urlopen(req, timeout=5).read().decode()
    except Exception:
        return CRIT, f"The {un} status service does not answer."
    status = re.search(r"<NewConnectionStatus>([^<]*)", x)
    up = re.search(r"<NewUptime>(\d+)", x)
    status = status.group(1) if status else "?"
    up = int(up.group(1)) if up else 0
    if status != "Connected":
        return CRIT, f"The {un} internet link is {status}."
    if up < c.get("recent_s", 900):
        return WARN, f"The {un} reconnected {up // 60} minutes ago."
    return OK, f"The {un} is connected, up for {up // 3600} h {up % 3600 // 60} min."


def ck_tailscale(c):
    try:
        p = subprocess.run([c.get("bin") or shutil.which("tailscale") or "tailscale", "status", "--json"],
                           capture_output=True, text=True, timeout=8)
        st = json.loads(p.stdout).get("BackendState")
    except Exception:
        return UNKNOWN, "Could not read Tailscale status."
    return (OK, "Tailscale on the collector is running.") if st == "Running" else (CRIT, f"Tailscale on the collector is {st}.")


def ck_newdev(c):
    with dbm.reader() as r:
        n = r.execute("SELECT count(*) FROM device WHERE known=0").fetchone()[0]
    return (OK, "No unreviewed devices.") if n == 0 else (WARN, f"{n} new device(s) to review on the Devices page.")


def ck_vpn(c):
    from .vpn import vpn_expect, vpn_status
    exp = vpn_expect()
    if not exp:
        return OK, "No device is marked as needing a VPN."
    bad = [v for v in vpn_status() if v["mac"] in exp and v["status"] in ("direct", "leak")]
    if bad:
        return WARN, "; ".join(f"{v['name']} is {'leaking outside its VPN' if v['status'] == 'leak' else 'not on its VPN'}"
                               for v in bad) + "."
    return OK, "Every device marked for a VPN is on it, or idle."


def ck_machines(c):
    from .health import machines_check
    return machines_check()


def ck_selftest(c):
    from .health import selftest_latest
    d = selftest_latest()
    if not d:
        return WARN, "The self-test has not run yet."
    age = time.time() - d["ts"]
    if age > c.get("stale_s", 2700):
        return CRIT, f"The self-test last ran {int(age // 60)} minutes ago; it should run every 15 minutes."
    n = d["counts"]
    failing = [r["title"] for r in d.get("results", []) if r.get("hard") == "FAIL"]
    if failing:
        return WARN, f"{len(failing)} failing: " + "; ".join(failing)[:300]
    return OK, f"{n['pass']} tests passed at {fmt_time(d['ts'])}" + (f", {n['warn']} warnings." if n.get("warn") else ".")


CHECKS = {"ping": ck_ping, "http": ck_http, "dns": ck_dns, "tcp": ck_tcp, "tls": ck_tls, "router": ck_router,
          "feed": ck_feed, "disk": ck_disk, "dbsize": ck_dbsize, "igd": ck_igd, "tailscale": ck_tailscale,
          "newdevices": ck_newdev, "ports": ck_ports, "vpn": ck_vpn, "machines": ck_machines, "selftest": ck_selftest}


def run_one(c):
    fn = CHECKS.get(c.get("kind"))
    if not fn:
        return UNKNOWN, f"Unknown check kind {c.get('kind')}."
    try:
        return fn(c)
    except Exception as e:
        return UNKNOWN, f"Check failed to run: {e.__class__.__name__}: {e}"


def checks_loop(db):
    conf = config.checks()
    nxt = {c["name"]: time.time() + 20 for c in conf}
    busy = set()
    lock = threading.Lock()

    def run(c):
        st, out = run_one(c)
        try:
            record(db, c, st, out)
        except Exception:
            LOG.exception("check %s", c["name"])
        with lock:
            busy.discard(c["name"])

    with concurrent.futures.ThreadPoolExecutor(4) as ex:
        while not STOP.is_set():
            now = time.time()
            for c in conf:
                if now >= nxt[c["name"]] and c["name"] not in busy:
                    nxt[c["name"]] = now + c.get("every", 60)
                    with lock:
                        busy.add(c["name"])
                    ex.submit(run, c)
            forced = db.meta("force_check")
            if forced:
                db.run("DELETE FROM meta WHERE k='force_check'")
                if forced in nxt:
                    nxt[forced] = 0
            STOP.wait(2)


def record(db, c, st, out):
    """Stores one result, counts attempts, and raises an event when the hard state changes."""
    now = int(time.time())
    name = c["name"]
    row = db.one("SELECT state, hard, attempts, since FROM check_state WHERE name=?", (name,))
    max_att = c.get("attempts", 3)
    if row is None:
        db.run("INSERT INTO check_state VALUES(?,?,?,?,?,?,?)", (name, st, st, 1, now, now, out))
        if st in (WARN, CRIT):
            event(db, now, c, None, st, out)
        return
    prev_state, hard, att, since = row
    if st == OK:
        att, new_hard = 1, OK
    else:
        att = att + 1 if st == prev_state or prev_state != OK else 1
        new_hard = st if att >= max_att else hard
    if new_hard != hard:
        since = now
        note = heal.on_check(db, c, hard, new_hard, out)
        if note:
            out = f"{out} {note}"
        event(db, now, c, hard, new_hard, out)
    db.run("UPDATE check_state SET state=?, hard=?, attempts=?, since=?, last_run=?, output=? WHERE name=?",
           (st, new_hard, min(att, max_att), since, now, out, name))


def event(db, now, c, old, new, out):
    title = c.get("title", c["name"])
    db.event(now, "check", c["name"], new, f"{title}: {STATE_NAME[new]}. {out}")
    LOG.info("check %s -> %s: %s", c["name"], STATE_NAME[new], out)
    if new == CRIT or (old == CRIT and new == OK):
        verb = "is CRITICAL" if new == CRIT else "has recovered"
        alerts.notify(f"check-{c['name']}", f"{config.BRAND}: {title} {verb}",
                      f"{title} {verb} at {fmt_time(now)}.\n\n{out}\n\n"
                      f"Open {config.BRAND} on {CFG['collector'].get('name') or 'the collector'} for detail: "
                      f"{config.collector_url()}", 1800)


def titles():
    return {c["name"]: c.get("title", c["name"]) for c in config.checks()}
