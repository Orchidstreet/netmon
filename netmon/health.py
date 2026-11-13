# SPDX-License-Identifier: AGPL-3.0-or-later
"""Machine health and self-test results: read-only facts about the collector, the router and
other machines, judged into plain-English findings.

Touches: runs the health script (CFG["health"]["script"], default health/netmon-health.sh) on the
collector; asks the router for `health` through router.py; accepts pushed reports on
/api/health/report from machines listed in CFG["health_machines"] (each with its own token, of which
only the SHA-256 is kept, and only from its own addresses); hands out a one-time installer from
<data_dir>/health/pending/<id>.token; reads the self-test's latest.json and selftest.db.
Writes the health_min and meta tables. Nothing here installs or changes anything on a machine.

Report format: one fact per line, fields separated by "|", e.g. "disk|/|apfs|<size_kb>|<used_kb>|<avail_kb>".
"""
import collections
import datetime
import hashlib
import hmac
import json
import os
import re
import subprocess
import threading
import time

from . import config, router, state
from .config import CFG
from .state import LOG, STOP

HEALTH = {}           # machine -> {"ts", "via", "facts", "net", "rx_bps", "tx_bps"}
HEALTH_LOCK = threading.Lock()


def script_path():
    return CFG["health"].get("script") or os.path.join(config.ROOT, "health", "netmon-health.sh")


def machines():
    """Configured machines, plus the collector and the router when the list is empty."""
    hm = config.health_machines()
    if hm:
        return hm
    return {"collector": {"name": CFG["collector"].get("name") or "collector", "via": "local"},
            "router": {"name": config.router_name(), "via": "gate"}}


def parse_health(text):
    f = {"disks": [], "pools": [], "temps": [], "nets": [], "addrs": [], "smart": [], "therm": {}, "posture": {},
         "upd_os": [], "pkgs": [], "vers": [], "reboot": None, "backup": None}
    num = lambda x, t=float: t(x) if x not in ("", None) else None
    for line in text.splitlines()[:500]:
        p = [re.sub(r"[\x00-\x1f\x7f]", "", x).strip()[:300] for x in line.split("|")]
        k = p[0]
        try:
            if k == "v": f["reported"] = int(p[2])
            elif k == "host": f["host"], f["hostname"] = p[1], (p[2] if len(p) > 2 else "")
            elif k == "os": f["os"], f["kernel"] = p[1], (p[2] if len(p) > 2 else "")
            elif k == "model": f["model"], f["cpu"] = p[1], (p[2] if len(p) > 2 else "")
            elif k == "uptime": f["uptime"] = int(p[1])
            elif k == "load": f["load"] = [float(x) for x in p[1:4]]
            elif k == "cpus": f["cpus"] = int(p[1])
            elif k == "mem": f["mem"] = {"total_kb": int(p[1]), "avail_kb": int(p[2]), "pressure": p[3] if len(p) > 3 and p[3] else None}
            elif k == "swap": f["swap"] = {"total_kb": int(p[1]), "used_kb": int(p[2])}
            elif k == "disk": f["disks"].append({"mount": p[1], "fs": p[2], "size_kb": int(p[3]), "used_kb": int(p[4]), "avail_kb": int(p[5])})
            elif k == "pool": f["pools"].append({"name": p[1], "size": int(p[2]), "alloc": int(p[3]), "free": int(p[4]), "health": p[5]})
            elif k == "temp": f["temps"].append({"label": p[1], "c": float(p[2])})
            elif k == "therm": f["therm"][p[1]] = p[2]
            elif k == "batt": f["batt"] = {"cycles": int(p[1]), "health_pct": num(p[2]), "temp_c": num(p[3]), "power": p[4],
                                           "charge_pct": num(p[5], int) if len(p) > 5 else None}
            elif k == "smart": f["smart"].append({"disk": p[1], "status": p[2]})
            elif k == "net": f["nets"].append({"iface": p[1], "rx": int(p[2]), "tx": int(p[3]), "mac": p[4].lower() if len(p) > 4 else ""})
            elif k == "addr": f["addrs"].append({"iface": p[1], "ip": p[2], "mac": p[3].lower() if len(p) > 3 else ""})
            elif k == "upd": f["upd_os"].append({"label": p[2], "kind": p[1], "restart": len(p) > 3 and p[3] == "restart"})
            elif k == "updc": f["pkgs"].append({"kind": p[1], "count": int(p[2] or 0), "lists_ts": num(p[3], int) or None,
                                                "names": p[4].split() if len(p) > 4 else [],
                                                "security": num(p[5], int) if len(p) > 5 else None})
            elif k == "posture": f["posture"][p[1]] = p[2]
            elif k == "reboot": f["reboot"] = p[2] if len(p) > 2 else "yes"
            elif k == "ver": f["vers"].append(p[2])
            elif k == "backup" and p[2]:
                m = re.search(r"(\d{4}-\d{2}-\d{2})-(\d{2})(\d{2})(\d{2})", p[2])
                f["backup"] = int(datetime.datetime.strptime(" ".join(m.groups()), "%Y-%m-%d %H %M %S").timestamp()) if m else None
        except (ValueError, IndexError, AttributeError):
            continue
    return f


def assess_health(mid, h, now):
    """Plain-English findings for one machine: [severity 0 ok / 1 warn / 2 crit, area, text]."""
    out = []
    add = lambda sev, area, text: out.append([sev, area, text])
    f, age = h["facts"], now - h["ts"]
    if age > 900:
        add(2 if age > 3600 else 1, "report", f"No report for {age // 60} minutes.")
    for d in f["disks"]:
        tot = d["used_kb"] + d["avail_kb"]
        pct = 100 * d["used_kb"] / tot if tot else 0
        if d["fs"] in ("ram", "iso9660"):
            continue
        gb = d["avail_kb"] / 1048576
        if pct >= 95: add(2, "disk", f"{d['mount']} is {pct:.0f}% full ({gb:.1f} GB free).")
        elif pct >= 85: add(1, "disk", f"{d['mount']} is {pct:.0f}% full ({gb:.1f} GB free).")
    for p in f["pools"]:
        if p["health"] != "ONLINE": add(2, "disk", f"ZFS pool {p['name']} is {p['health']}.")
        elif p["size"] and p["alloc"] / p["size"] > .85: add(1, "disk", f"ZFS pool {p['name']} is {100 * p['alloc'] / p['size']:.0f}% full.")
    m = f.get("mem") or {}
    if m.get("pressure") in ("warning", "critical"):
        add(2 if m["pressure"] == "critical" else 1, "memory", f"The system reports memory pressure: {m['pressure']}.")
    sw = f.get("swap") or {}
    if sw.get("total_kb") and sw["used_kb"] / sw["total_kb"] > .75:
        add(1, "memory", f"Swap {100 * sw['used_kb'] / sw['total_kb']:.0f}% used: the machine is short of memory.")
    for t in f["temps"]:
        lim = 95 if "GPU" in t["label"] else 90
        if t["c"] >= lim: add(2, "heat", f"{t['label']} at {t['c']:.0f} °C.")
        elif t["c"] >= lim - 10: add(1, "heat", f"{t['label']} at {t['c']:.0f} °C.")
    th = f["therm"].get("cpu_speed_limit")
    if th and th.isdigit() and int(th) < 100:
        add(1, "heat", f"The CPU is slowed to {th}% to keep cool.")
    b = f.get("batt")
    if b and b.get("health_pct") and b["health_pct"] < 80:
        add(1, "battery", f"Battery holds {b['health_pct']:.0f}% of its original charge ({b['cycles']} cycles).")
    if h.get("via") == "local" and b and b.get("power") == "battery":
        c = b.get("charge_pct")
        add(2, "power", f"The collector is running on battery ({c if c is not None else '?'}% left). Check its power supply.")
    for sm in f["smart"]:
        if sm["status"] and sm["status"].lower() not in ("verified", "passed", "ok"):
            add(2, "disk", f"Disk {sm['disk']} self-test says: {sm['status']}.")
    if f["upd_os"]:
        add(1, "updates", f"{len(f['upd_os'])} system update{'s' if len(f['upd_os']) > 1 else ''} waiting: "
                          f"{', '.join(u['label'] for u in f['upd_os'][:2])}"
                          f"{' (restart needed)' if any(u['restart'] for u in f['upd_os']) else ''}.")
    for pk in f["pkgs"]:
        if pk.get("security"): add(1, "updates", f"{pk['security']} security update{'s' if pk['security'] > 1 else ''} waiting ({pk['kind']}).")
        elif pk["count"] >= 15: add(1, "updates", f"{pk['count']} {pk['kind']} packages out of date.")
    if f["reboot"]:
        add(1, "updates", "A restart is needed to finish installing updates.")
    po = f["posture"]
    if "FileVault is Off" in po.get("filevault", ""): add(1, "security", "FileVault is off: the internal disk is not encrypted.")
    if "disabled" in po.get("firewall", ""): add(1, "security", "The macOS firewall is off.")
    if "disabled" in po.get("sip", ""): add(2, "security", "System Integrity Protection is off.")
    if "disabled" in po.get("gatekeeper", ""): add(1, "security", "Gatekeeper is off: unsigned apps can run.")
    if po.get("auto_security") == "0": add(1, "security", "Automatic security responses are off.")
    if po.get("unattended_upgrades") == "missing": add(1, "security", "Automatic security updates are not installed.")
    if po.get("ssh_password_auth") == "on": add(1, "security", "SSH password login is on.")
    return sorted(out, key=lambda x: -x[0])


def ingest_health(db, mid, text, via):
    now = int(time.time())
    f = parse_health(text)
    if not f.get("host"):
        raise ValueError("no host line in the report")
    with HEALTH_LOCK:
        old = HEALTH.get(mid) or {}
        rx = sum(n["rx"] for n in f["nets"])
        tx = sum(n["tx"] for n in f["nets"])
        rb = tb = None
        pn = old.get("net")
        if pn and now > pn[0] and rx >= pn[1] and tx >= pn[2]:
            rb, tb = (rx - pn[1]) * 8 / (now - pn[0]), (tx - pn[2]) * 8 / (now - pn[0])
        HEALTH[mid] = {"ts": now, "via": via, "facts": f, "net": (now, rx, tx), "rx_bps": rb, "tx_bps": tb}
    rows = [(now, mid, "load1", (f.get("load") or [None])[0]), (now, mid, "rx_bps", rb), (now, mid, "tx_bps", tb)]
    m = f.get("mem") or {}
    if m.get("total_kb"):
        rows.append((now, mid, "mem_used_pct", 100 - 100 * m["avail_kb"] / m["total_kb"]))
    for d in f["disks"]:
        tot = d["used_kb"] + d["avail_kb"]
        if tot and d["fs"] not in ("ram", "iso9660"):
            rows.append((now, mid, "disk:" + d["mount"], 100 * d["used_kb"] / tot))
    if f["temps"]:
        rows.append((now, mid, "temp_max", max(t["c"] for t in f["temps"])))
    if f.get("batt") and f["batt"].get("temp_c") is not None:
        rows.append((now, mid, "batt_temp", f["batt"]["temp_c"]))
    db.many("INSERT OR REPLACE INTO health_min VALUES(?,?,?,?)", [r for r in rows if r[3] is not None])
    db.set_meta("health_raw_" + mid, json.dumps({"ts": now, "via": via, "text": text[:65536]}))


def health_collect(mid, via):
    if via == "local":
        if not os.path.isfile(script_path()):
            return None
        cache = os.path.join(config.data_dir(), "health-cache")
        p = subprocess.run(["/bin/sh", script_path()], capture_output=True, text=True, timeout=150,
                           env={**os.environ, "NETMON_HEALTH_CACHE": cache})
        return p.stdout
    if via == "gate":
        rc, out = router.gate("health", timeout=60)
        return out if rc == 0 else None
    return None


def health_loop(db):
    ms = machines()
    for mid in ms:
        try:
            raw = json.loads(db.meta("health_raw_" + mid) or "null")
            if raw:
                HEALTH[mid] = {"ts": raw["ts"], "via": raw["via"], "facts": parse_health(raw["text"]), "net": None,
                               "rx_bps": None, "tx_bps": None}
        except Exception:
            pass
    STOP.wait(20)
    while not STOP.is_set():
        for mid, m in ms.items():
            if m.get("via") in ("local", "gate"):
                try:
                    out = health_collect(mid, m["via"])
                    if out:
                        ingest_health(db, mid, out, m["via"])
                except Exception as e:
                    LOG.warning("health %s: %s", mid, e)
        STOP.wait(300)


def api_health_report(peer, headers, body):
    """A pushed report from one machine: its own token, from its own addresses only."""
    mid = (headers.get("X-Health-Machine") or "").strip()
    m = machines().get(mid)
    if not m or m.get("via") != "push" or not m.get("token_sha256"):
        return 403, {"error": "unknown machine"}
    if str(peer) not in m.get("ips", []):
        LOG.warning("health report for %s refused from %s", mid, peer)
        return 403, {"error": "wrong address"}
    tok = (headers.get("X-Health-Token") or "").strip()
    if not hmac.compare_digest(hashlib.sha256(tok.encode()).hexdigest(), m["token_sha256"]):
        LOG.warning("health report for %s with a bad token from %s", mid, peer)
        return 403, {"error": "bad token"}
    if time.time() - (HEALTH.get(mid) or {}).get("ts", 0) < 60:
        return 429, {"error": "too soon"}
    ingest_health(state.DBW, mid, body.decode("utf-8", "replace"), "push")
    return 200, {"ok": True}


HEALTH_INSTALLER = r"""#!/bin/sh
# netmon machine health reporter for @NAME@ (read-only).
# Every 5 minutes it sends a read-only health report (disk, memory, temperatures, battery, pending updates,
# security settings) to netmon. It installs into your own account only and changes nothing else. Remove it with:
#   launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.netmon.health.plist; rm -rf ~/.netmon-health ~/Library/LaunchAgents/com.netmon.health.plist
set -e
[ "$(uname -s)" = Darwin ] || { echo "This installer is for macOS."; exit 1; }
D="$HOME/.netmon-health"; P="$HOME/Library/LaunchAgents/com.netmon.health.plist"
umask 077; mkdir -p "$D/cache" "$HOME/Library/LaunchAgents"
cat > "$D/netmon-health.sh" <<'NETMON_EOF'
@SCRIPT@NETMON_EOF
printf 'X-Health-Machine: %s\nX-Health-Token: %s\n' '@ID@' '@TOKEN@' > "$D/headers"
cat > "$D/report.sh" <<'NETMON_EOF'
#!/bin/sh
D="$HOME/.netmon-health"
NETMON_HEALTH_CACHE="$D/cache" /bin/sh "$D/netmon-health.sh" 2>/dev/null | /usr/bin/curl -s -m 30 -X POST -H @"$D/headers" -H "Content-Type: text/plain" --data-binary @- '@URL@' >/dev/null 2>&1
NETMON_EOF
chmod 700 "$D/report.sh"
cat > "$P" <<NETMON_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.netmon.health</string>
  <key>ProgramArguments</key><array><string>/bin/sh</string><string>$D/report.sh</string></array>
  <key>StartInterval</key><integer>300</integer>
  <key>RunAtLoad</key><true/>
  <key>Nice</key><integer>10</integer>
  <key>LowPriorityIO</key><true/>
  <key>StandardOutPath</key><string>/dev/null</string>
  <key>StandardErrorPath</key><string>/dev/null</string>
</dict></plist>
NETMON_EOF
launchctl bootout "gui/$(id -u)" "$P" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$P"
echo "netmon health reporter installed for @NAME@. The first report arrives within a minute."
"""


def health_installer(mid, peer):
    """The one-time installer for a push machine: only from that machine's own address, and only while a
    pending token exists. The token file is deleted as soon as the installer is handed out."""
    m = machines().get(mid)
    pend = os.path.join(config.data_dir(), "health", "pending", os.path.basename(mid or "x") + ".token")
    if not m or m.get("via") != "push" or str(peer) not in m.get("ips", []) or not os.path.isfile(pend) \
            or not os.path.isfile(script_path()):
        return None
    tok = open(pend).read().strip()
    with open(script_path()) as fh:
        script = fh.read()
    url = m.get("url") or config.collector_url().rstrip("/") + "/api/health/report"
    body = (HEALTH_INSTALLER.replace("@SCRIPT@", script if script.endswith("\n") else script + "\n").replace("@ID@", mid)
            .replace("@TOKEN@", tok).replace("@URL@", url).replace("@NAME@", m.get("name") or mid))
    os.remove(pend)
    LOG.info("health installer for %s handed to %s; pending token removed", mid, peer)
    state.DBW.event(int(time.time()), "health", mid, 1, f"Health reporter installer fetched by {m.get('name') or mid} ({peer})")
    return body


def machines_check():
    from .checks import CRIT, OK
    now = int(time.time())
    bad = []
    ms = machines()
    for mid, m in ms.items():
        h = HEALTH.get(mid)
        if not h or m.get("on_demand"):
            continue
        crit = [x for x in assess_health(mid, h, now) if x[0] == 2]
        if crit:
            bad.append(f"{m.get('name') or mid}: {crit[0][2]}")
    if bad:
        return CRIT, " ".join(bad)
    return OK, f"{sum(1 for k in ms if k in HEALTH)} machines reporting, nothing critical."


def health_view(span):
    from .db import reader
    now = int(time.time())
    with reader() as r:
        hist = collections.defaultdict(lambda: collections.defaultdict(list))
        for ts, mid, k, v in r.execute("SELECT ts, machine, k, v FROM health_min WHERE ts >= ? ORDER BY ts", (now - span,)):
            hist[mid][k].append([ts, round(v, 2)])
        week = collections.defaultdict(dict)
        for mid, k, t0, v0, t1, v1 in r.execute(
                "SELECT machine, k, min(ts), (SELECT v FROM health_min h2 WHERE h2.machine = h.machine AND h2.k = h.k ORDER BY ts LIMIT 1), "
                "max(ts), (SELECT v FROM health_min h3 WHERE h3.machine = h.machine AND h3.k = h.k ORDER BY ts DESC LIMIT 1) "
                "FROM health_min h WHERE k LIKE 'disk:%' AND ts >= ? GROUP BY machine, k", (now - 30 * 86400,)):
            if t1 - t0 >= 6 * 3600 and v1 > v0:
                week[mid][k[5:]] = (100 - v1) / ((v1 - v0) / (t1 - t0)) / 86400
    out = []
    for mid, m in machines().items():
        h = HEALTH.get(mid)
        e = {"id": mid, "name": m.get("name") or mid, "via": m.get("via"), "note": m.get("note"),
             "on_demand": bool(m.get("on_demand"))}
        if h:
            e.update(ts=h["ts"], age=now - h["ts"], facts=h["facts"], rx_bps=h["rx_bps"], tx_bps=h["tx_bps"],
                     findings=assess_health(mid, h, now), history=hist.get(mid, {}), full_in_days=week.get(mid, {}))
        out.append(e)
    return {"now": now, "span": span, "machines": out}


# ---------------------------------------------------------------- self-test results

ST_CACHE = {"mtime": 0, "data": None}


def selftest_dir():
    return CFG["selftest"].get("data_dir") or os.path.join(config.data_dir(), "selftest")


def selftest_queue():
    return CFG["selftest"].get("queue_dir") or os.path.join(CFG["collector"]["data_dir"], "selftest", "queue")


def selftest_latest():
    p = os.path.join(selftest_dir(), "latest.json")
    try:
        m = os.path.getmtime(p)
        if m != ST_CACHE["mtime"]:
            ST_CACHE.update(mtime=m, data=json.load(open(p)))
    except (OSError, ValueError):
        return None
    return ST_CACHE["data"]


def selftest_summary():
    d = selftest_latest()
    return {"ts": d["ts"], **d.get("counts", {})} if d else None
