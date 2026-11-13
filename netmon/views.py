# SPDX-License-Identifier: AGPL-3.0-or-later
"""Core API views: the live summary, traffic series, devices, applications, connections, DNS,
checks, the timeline and the small settings the web saves.

Touches: reads the database (read-only connections) and live state; the POST views write the
device label and known flags, the forced-check flag, the sidebar order, and the self-test queue
file. Each function takes the query dict (and the JSON body for POST) and returns a JSON-ready dict.
"""
import collections
import fcntl
import json
import os
import re
import sqlite3
import statistics
import threading
import time

from . import checks, config, health, state
from .classify import CLS, app_name, device_names, dns_clients, named
from .config import CFG
from .db import reader
from .dns import noise_clause
from .state import S, span

STARTED = int(time.time())


def api_now(q):
    now = int(time.time())
    noise = noise_clause()
    with S.lock:
        trace = [list(x) for x in S.trace if x[0] >= now - 1800]
        v = dict(S.vitals) if S.vitals else None
    with reader() as r:
        names = device_names(r)
        by_ip = dns_clients(r)
        devs = [dict(x) for x in r.execute(
            "SELECT mac, sum(down) down, sum(up) up FROM app_15s WHERE ts >= ? GROUP BY mac "
            "ORDER BY sum(down)+sum(up) DESC LIMIT 8", (now - 300,))]
        for d in devs:
            d.update(named(names, d["mac"]))
            top = r.execute("SELECT app, sum(down+up) b FROM app_15s WHERE ts >= ? AND mac=? "
                            "GROUP BY app ORDER BY b DESC LIMIT 3", (now - 300, d["mac"])).fetchall()
            d["apps"] = [{"app": app_name(a["app"]), "bytes": a["b"]} for a in top]
        apps = [dict(x) for x in r.execute(
            "SELECT app, sum(down) down, sum(up) up, count(DISTINCT mac) devices FROM app_15s "
            "WHERE ts >= ? GROUP BY app ORDER BY sum(down)+sum(up) DESC LIMIT 8", (now - 300,))]
        for a in apps:
            a["name"] = app_name(a["app"])
        dq = r.execute(f"SELECT count(*), sum(status='blocked'), sum(status='cached') FROM dns WHERE ts >= ? AND {noise}",
                       (now - 900,)).fetchone()
        rt = [x[0] for x in r.execute(f"SELECT reply_ms FROM dns WHERE ts >= ? AND {noise} AND status='forwarded' "
                                      "AND reply_ms IS NOT NULL", (now - 900,))]
        dseries = [list(x) for x in r.execute(
            f"SELECT ts/60*60 t, sum(status!='blocked'), sum(status='blocked') FROM dns WHERE ts >= ? AND {noise} "
            "GROUP BY t ORDER BY t", (now - 1800,))]
        chk = [dict(x) for x in r.execute("SELECT name, hard, output, since FROM check_state")]
        events = [dict(x) for x in r.execute("SELECT * FROM event ORDER BY ts DESC LIMIT 8")]
        new_devices = r.execute("SELECT count(*) FROM device WHERE known=0").fetchone()[0]
    titles = checks.titles()
    counts = collections.Counter(c["hard"] for c in chk)
    problems = sorted([dict(c, title=titles.get(c["name"], c["name"])) for c in chk if c["hard"]], key=lambda c: -c["hard"])
    return {"now": now, "site": config.site(), "trace": trace, "router": v,
            "vitals_age": now - S.vitals_ts if S.vitals_ts else None,
            "feed": {"age": now - S.feed_ts if S.feed_ts else None, "status": S.feed_status},
            "devices": devs, "apps": apps,
            "dns": {"queries": dq[0] or 0, "blocked": dq[1] or 0, "cached": dq[2] or 0, "window": 900,
                    "reply_ms": statistics.median(rt) if rt else None, "series": dseries,
                    "live": [dict(x, device=by_ip.get(x["client"], x["client"])) for x in list(S.live_dns)[-14:][::-1]],
                    "pihole": None},
            "checks": {"ok": counts[checks.OK], "warn": counts[checks.WARN], "crit": counts[checks.CRIT],
                       "unknown": counts[checks.UNKNOWN], "problems": problems},
            "events": events, "latency": S.latency, "new_devices": new_devices, "selftest": health.selftest_summary()}


def bucket_for(sp):
    return 60 if sp <= 21600 else 300 if sp <= 86400 else 1800 if sp <= 604800 else 7200 if sp <= 2592000 else 86400


def api_series(q):
    sp = span(q)
    now = int(time.time())
    b = bucket_for(sp)
    with reader() as r:
        rows = r.execute(
            f"SELECT ts/{b}*{b} t, avg(down), avg(up), max(down_max), max(up_max), avg(cpu), max(cpu_max), "
            f"avg(temp), min(mem_avail), max(conntrack), max(wifi) FROM vitals_min WHERE ts >= ? "
            f"GROUP BY t ORDER BY t", (now - sp,)).fetchall()
    return {"bucket": b, "cols": ["t", "down", "up", "down_max", "up_max", "cpu", "cpu_max", "temp", "mem_avail",
                                  "conntrack", "wifi"], "rows": [list(x) for x in rows]}


def api_latency(q):
    sp = span(q)
    now = int(time.time())
    b = bucket_for(sp)
    out = {}
    targets = config.latency_targets()
    with reader() as r:
        for t in targets:
            rows = r.execute(
                f"SELECT ts/{b}*{b} t, min(rtt_min), avg(rtt_med), max(rtt_max), avg(loss) FROM latency_min "
                f"WHERE target=? AND ts >= ? GROUP BY t ORDER BY t", (t["name"], now - sp)).fetchall()
            out[t["name"]] = [list(x) for x in rows]
    return {"bucket": b, "targets": [t["name"] for t in targets], "series": out}


def api_devices(q):
    sp = span(q)
    now = int(time.time())
    with reader() as r:
        names = device_names(r)
        tot = {x["mac"]: dict(x) for x in r.execute(
            "SELECT mac, sum(down) down, sum(up) up FROM app_min WHERE ts >= ? GROUP BY mac", (now - sp,))}
        top = {}
        for x in r.execute("SELECT mac, app, sum(down+up) b FROM app_min WHERE ts >= ? AND app NOT LIKE '0.%' "
                           "GROUP BY mac, app ORDER BY b DESC", (now - sp,)):
            top.setdefault(x["mac"], app_name(x["app"]))
        out = []
        for d in r.execute("SELECT * FROM device ORDER BY last_seen DESC"):
            t = tot.get(d["mac"], {})
            out.append({"mac": d["mac"], "name": names[d["mac"]]["name"], "hostname": d["hostname"],
                        "label": d["label"], "ip": d["ip"], "vendor": d["vendor"], "known": d["known"],
                        "first_seen": d["first_seen"], "last_seen": d["last_seen"],
                        "down": t.get("down", 0), "up": t.get("up", 0), "top_app": top.get(d["mac"], ""),
                        "link": S.links.get(d["mac"])})
    ports = sorted(S.ports.values(), key=lambda p: (p["wan"], p["name"]))
    out.sort(key=lambda d: -(d["down"] + d["up"]))
    return {"devices": out, "ports": ports}


def enrich(c):
    """Best available name for a destination, where it came from, and its application."""
    if c.get("domain"):
        c["name"], c["name_src"] = c["domain"], "DNS"
    elif c.get("rname"):
        c["name"], c["name_src"] = c["rname"], "reverse DNS"
    else:
        c["name"], c["name_src"] = "", ""
    c["app"], c["app_via"] = CLS.classify(c["dst"], c["name"])


def api_device(q):
    mac = q.get("mac", "")
    sp = span(q)
    now = int(time.time())
    b = bucket_for(sp)
    with reader() as r:
        d = r.execute("SELECT * FROM device WHERE mac=?", (mac,)).fetchone()
        if not d:
            return {"error": "No such device."}
        apps = [dict(x) for x in r.execute(
            "SELECT app, sum(down) down, sum(up) up FROM app_min WHERE mac=? AND ts >= ? GROUP BY app "
            "ORDER BY sum(down)+sum(up) DESC LIMIT 25", (mac, now - sp))]
        for a in apps:
            a["name"] = app_name(a["app"])
        series = [list(x) for x in r.execute(
            f"SELECT ts/{b}*{b} t, sum(down), sum(up) FROM app_min WHERE mac=? AND ts >= ? GROUP BY t ORDER BY t",
            (mac, now - sp))]
        domains = [dict(x) for x in r.execute(
            "SELECT domain, count(*) n, sum(status='blocked') blocked, max(ts) last FROM dns "
            "WHERE client=? AND ts >= ? GROUP BY domain ORDER BY n DESC LIMIT 40", (d["ip"], now - sp))]
        peers = [dict(x) for x in r.execute(
            "SELECT c.dst, c.dport, c.proto, sum(c.bytes_up) up, sum(c.bytes_down) down, max(c.last) last, "
            "count(*) conns, n.domain, d.name rname FROM conn c LEFT JOIN ip_name n ON n.ip=c.dst "
            "LEFT JOIN rdns d ON d.ip=c.dst "
            "WHERE c.src=? AND c.last >= ? GROUP BY c.dst, c.dport, c.proto ORDER BY down+up DESC LIMIT 40",
            (d["ip"], now - sp))]
    for p in peers:
        enrich(p)
    return {"device": dict(d, name=d["label"] or d["hostname"] or d["vendor"] or "Unknown device"),
            "apps": apps, "bucket": b, "series": series, "domains": domains, "peers": peers}


def api_apps(q):
    sp = span(q)
    now = int(time.time())
    with reader() as r:
        names = device_names(r)
        apps = [dict(x) for x in r.execute(
            "SELECT app, sum(down) down, sum(up) up, count(DISTINCT mac) devices FROM app_min WHERE ts >= ? "
            "GROUP BY app ORDER BY sum(down)+sum(up) DESC LIMIT 200", (now - sp,))]
        first = {x[0]: x[1] for x in r.execute("SELECT app, first FROM app_seen")}
        base = r.execute("SELECT v FROM meta WHERE k='apps_baseline_until'").fetchone()
        users = collections.defaultdict(list)
        for x in r.execute("SELECT app, mac, sum(down+up) b FROM app_min WHERE ts >= ? GROUP BY app, mac ORDER BY b DESC",
                           (now - sp,)):
            if len(users[x["app"]]) < 4:
                users[x["app"]].append({"name": names.get(x["mac"], {"name": x["mac"]})["name"], "bytes": x["b"]})
    for a in apps:
        a["name"] = app_name(a["app"])
        a["users"] = users[a["app"]]
        a["first_seen"] = first.get(a["app"])
    return {"apps": apps, "apps_baseline": float(base[0]) if base else 0}


def api_conns(q):
    now = int(time.time())
    with reader() as r:
        names = device_names(r)
        by_ip = {v["ip"]: v["name"] for v in names.values() if v["ip"]}
        rows = [dict(x) for x in r.execute(
            "SELECT c.*, n.domain, d.name rname FROM conn c LEFT JOIN ip_name n ON n.ip=c.dst "
            "LEFT JOIN rdns d ON d.ip=c.dst WHERE c.last >= ? ORDER BY c.bytes_down + c.bytes_up DESC LIMIT 400",
            (now - 90,))]
    for c in rows:
        c["device"] = by_ip.get(c["src"], c["src"])
        enrich(c)
    return {"conns": rows}


def api_dns(q):
    sp = span(q)
    noise = noise_clause()
    now = int(time.time())
    b = bucket_for(sp) if sp > 3600 else 60
    with reader() as r:
        by_ip = dns_clients(r)
        w = (now - sp,)
        tot = r.execute("SELECT count(*), sum(status='blocked'), sum(status='cached'), sum(status='forwarded'), "
                        f"count(DISTINCT client) FROM dns WHERE ts >= ? AND {noise}", w).fetchone()
        rt = sorted(x[0] for x in r.execute(f"SELECT reply_ms FROM dns WHERE ts >= ? AND {noise} AND status='forwarded' "
                                            "AND reply_ms IS NOT NULL", w))
        series = [list(x) for x in r.execute(
            f"SELECT ts/{b}*{b} t, sum(status!='blocked'), sum(status='blocked') FROM dns WHERE ts >= ? AND {noise} "
            "GROUP BY t ORDER BY t", w)]
        top = [dict(x) for x in r.execute(
            f"SELECT domain, count(*) n, count(DISTINCT client) clients FROM dns WHERE ts >= ? AND {noise} "
            "AND status!='blocked' GROUP BY domain ORDER BY n DESC LIMIT 15", w)]
        blocked = [dict(x) for x in r.execute(
            f"SELECT domain, count(*) n, count(DISTINCT client) clients FROM dns WHERE ts >= ? AND {noise} "
            "AND status='blocked' GROUP BY domain ORDER BY n DESC LIMIT 15", w)]
        clients = [dict(x) for x in r.execute(
            f"SELECT client, count(*) n, sum(status='blocked') blocked FROM dns WHERE ts >= ? AND {noise} "
            "GROUP BY client ORDER BY n DESC LIMIT 12", w)]
        types = [dict(x) for x in r.execute(
            f"SELECT qtype, count(*) n FROM dns WHERE ts >= ? AND {noise} GROUP BY qtype ORDER BY n DESC LIMIT 8", w)]
        upstreams = [dict(x) for x in r.execute(
            f"SELECT upstream, count(*) n, avg(reply_ms) ms FROM dns WHERE ts >= ? AND {noise} AND status='forwarded' "
            "AND upstream IS NOT NULL GROUP BY upstream ORDER BY n DESC LIMIT 5", w)]
    for c in clients:
        c["device"] = by_ip.get(c["client"], c["client"])
    live = [dict(x) for x in list(S.live_dns)[-80:][::-1]]
    for x in live:
        x["device"] = by_ip.get(x["client"], x["client"])
    return {"bucket": b, "series": series, "top": top, "blocked": blocked, "clients": clients, "types": types,
            "upstreams": upstreams, "live": live, "pihole": None,
            "total": tot[0] or 0, "blocked_total": tot[1] or 0, "cached_total": tot[2] or 0,
            "forwarded_total": tot[3] or 0, "client_count": tot[4] or 0,
            "reply_ms": rt[len(rt) // 2] if rt else None}


def api_checks(q):
    with reader() as r:
        st = {x["name"]: dict(x) for x in r.execute("SELECT * FROM check_state")}
        events = [dict(x) for x in r.execute("SELECT * FROM event ORDER BY ts DESC LIMIT 100")]
    out = []
    for c in config.checks():
        s = st.get(c["name"], {})
        out.append({"name": c["name"], "title": c.get("title", c["name"]), "group": c.get("group", "Other"),
                    "every": c.get("every", 60), "state": s.get("hard", checks.UNKNOWN), "soft": s.get("state"),
                    "attempts": s.get("attempts", 0), "max_attempts": c.get("attempts", 3),
                    "since": s.get("since"), "last_run": s.get("last_run"), "output": s.get("output", "Not run yet.")})
    return {"checks": out, "events": events}


def api_timeline(q):
    """Everything netmon noticed, in time order: VPN switches, check changes, new devices and apps,
    machine-health installs and load tests."""
    sp = span(q)
    now = int(time.time())
    t0 = now - sp
    with reader() as r:
        ev = [list(x) for x in r.execute("SELECT ts, kind, subject, state, text FROM event WHERE ts >= ? ORDER BY ts", (t0,))]
        tests = [json.loads(x[0]) for x in r.execute("SELECT result FROM bloat_test WHERE ts >= ? ORDER BY ts", (t0,))]
        chk = {x["name"]: dict(x) for x in r.execute("SELECT * FROM check_state")}
    for t in tests:
        if "grade" in t and t.get("added_ms") is not None:
            ev.append([t["ts"], "test", "bufferbloat", 1 if t["grade"].startswith("A") else 0,
                       f"Bufferbloat test: grade {t['grade']}, {t['added_ms']:.0f} ms added under load, "
                       f"{t['down_mbps']:.0f} down / {t['up_mbps']:.0f} up Mbit/s"])
    ev.sort(key=lambda e: e[0])
    titles = checks.titles()
    return {"now": now, "span": sp, "events": ev, "titles": titles,
            "checks_now": [[n, titles.get(n, n), x["state"], x["since"]] for n, x in chk.items()]}


def api_skyline(q):
    """Traffic per device per time slot, for the 3D skyline."""
    sp = span(q, "6h")
    now = int(time.time())
    b = 300 if sp <= 21600 else 900 if sp <= 86400 else 3600 if sp <= 604800 else 21600
    t0 = (now - sp) // b * b
    with reader() as r:
        names = device_names(r)
        rows = r.execute(f"SELECT ts/{b}*{b} t, mac, app, sum(down) d, sum(up) u FROM app_min WHERE ts >= ? "
                         f"GROUP BY t, mac, app", (t0,)).fetchall()
    cells = {}
    for x in rows:
        c = cells.setdefault((x["t"], x["mac"]), {"d": 0, "u": 0, "top": None, "tb": -1})
        c["d"] += x["d"] or 0
        c["u"] += x["u"] or 0
        tb = (x["d"] or 0) + (x["u"] or 0)
        if tb > c["tb"] and not str(x["app"]).startswith("0."):
            c["tb"], c["top"] = tb, app_name(x["app"])
    totals = collections.Counter()
    for (t, m), c in cells.items():
        totals[m] += c["d"] + c["u"]
    macs = [m for m, _ in totals.most_common()]
    return {"bucket": b, "t0": t0, "t1": now, "now": now,
            "devices": [{"mac": m, **{k: v for k, v in named(names, m).items() if k in ("name", "ip", "vendor")},
                         "link": S.links.get(m)} for m in macs],
            "cells": [[t, m, c["d"], c["u"], c["top"]] for (t, m), c in sorted(cells.items())]}


def api_label(q, body):
    mac, label = body.get("mac", ""), (body.get("label") or "").strip()[:60]
    state.DBW.run("UPDATE device SET label=? WHERE mac=?", (label, mac))
    return {"ok": True}


def api_known(q, body):
    state.DBW.run("UPDATE device SET known=1 WHERE mac=?", (body.get("mac", ""),))
    return {"ok": True}


def api_runcheck(q, body):
    state.DBW.set_meta("force_check", body.get("name", ""))
    return {"ok": True}


NAV_TOKEN = re.compile(r"^(h:)?[A-Za-z0-9 &_.'-]{1,40}$")


def api_navorder(q):
    try:
        return {"order": json.loads(state.DBW.meta("nav_order") or "null")}
    except ValueError:
        return {"order": None}


def api_navorder_set(q, body):
    order = body.get("order")
    if order is None:
        state.DBW.set_meta("nav_order", "null")
        return {"ok": True, "order": None}
    if not isinstance(order, list) or len(order) > 120 or not all(isinstance(t, str) and NAV_TOKEN.match(t) for t in order):
        return {"ok": False, "error": "bad order"}
    state.DBW.set_meta("nav_order", json.dumps(order))
    return {"ok": True, "order": order}


def api_selftest(q):
    sd = health.selftest_dir()
    out = {"now": int(time.time()), "started": STARTED, "threads": sorted(t.name for t in threading.enumerate()),
           "latest": health.selftest_latest(), "runs": [], "strip": {}, "running": False}
    try:
        with open(os.path.join(sd, "run.lock"), "a") as lf:
            try:
                fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(lf, fcntl.LOCK_UN)
            except OSError:
                out["running"] = True
    except OSError:
        pass
    try:
        out["queued"] = bool(os.listdir(health.selftest_queue()))
    except OSError:
        out["queued"] = False
    try:
        p = os.path.join(sd, "selftest.db")
        if os.path.exists(p):
            c = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=5)
            out["runs"] = c.execute("SELECT ts, secs, pass, warn, fail, skip, how FROM runs ORDER BY ts DESC LIMIT 96").fetchall()[::-1]
            if out["runs"]:
                t0 = out["runs"][max(0, len(out["runs"]) - 24)][0]
                for tid, ts, st in c.execute("SELECT id, ts, status FROM results WHERE ts >= ? ORDER BY ts", (t0,)):
                    out["strip"].setdefault(tid, []).append([ts, st])
            if q.get("id"):
                out["history"] = c.execute("SELECT ts, status, detail FROM results WHERE id=? ORDER BY ts DESC LIMIT 96",
                                           (q["id"],)).fetchall()
            c.close()
    except sqlite3.Error:
        pass
    return out


def api_selftest_run(q, body):
    qd = health.selftest_queue()
    os.makedirs(qd, exist_ok=True)
    if not os.listdir(qd):
        with open(os.path.join(qd, "run-now"), "w") as f:
            f.write(str(int(time.time())))
    return {"ok": True, "queued": True}


def api_mind(q):
    """Not part of netmon: answers with an empty payload so an old page shows an empty state."""
    return {"now": int(time.time()), "error": "not available", "families": [], "facts": [], "edges": [], "events": [],
            "sessions": [], "revisions": [], "counts": {}, "hits": [], "open_sessions": 0}
