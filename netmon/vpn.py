# SPDX-License-Identifier: AGPL-3.0-or-later
"""VPN view: tunnel state, per-device VPN status, and where each connection left the site.

Touches: the router through router.py (`vpn status`, read-only); one HTTPS request to
CFG["vpn"]["ip_check_url"] to learn the public address (only while a VPN page is open or a switch
runs); the tunnel_min and event tables. It changes nothing; switching lives in heal.py.

tunnel_loop runs only when CFG["vpn"]["enabled"] is true. vpn_status combines live connections,
the latest packet captures (capture.py) and remembered tunnels into one status per device:
vpn, leak, or direct.
"""
import collections
import ipaddress
import json
import time
import urllib.request

from . import router
from .classify import ip_directory
from .config import CFG
from .db import reader
from .geo import geo_lookup
from .state import LOG, STOP
from . import state

TUN = {"last": None, "prev": None, "trace": collections.deque(maxlen=540), "minute": []}
VPNSW = {"busy": False, "last": None, "ip": None, "ip_ts": 0}
IP_CHECK_URL = "https://www.cloudflare.com/cdn-cgi/trace"


def vpn_switch_status():
    rc, out = router.vpn_status_raw()
    try:
        st = json.loads(out)
    except ValueError:
        return {"error": out[:120] or ("router unreachable" if rc == router.SSH_FAILED else "no answer")}
    if not isinstance(st, dict) or "gate" in st:
        return {"error": str(st)[:120]}
    st["on"] = st.get("enabled") == "1" and st.get("rule") in ("1", "", None)
    st["up"] = st["on"] and (st.get("handshake") or 0) > 0 and st.get("now", 0) - st["handshake"] < 180
    return st


def public_ip(force=False):
    """The address the internet sees for this site (cached for a minute)."""
    now = int(time.time())
    if not force and VPNSW["ip"] and now - VPNSW["ip_ts"] < 60:
        return VPNSW["ip"]
    try:
        url = CFG["vpn"].get("ip_check_url") or IP_CHECK_URL
        req = urllib.request.Request(url, headers={"User-Agent": "netmon"})
        out = urllib.request.urlopen(req, timeout=8).read().decode("utf-8", "replace")
        kv = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
        ip = kv.get("ip")
        if ip:
            cc, asn, org = geo_lookup(ip)
            VPNSW.update(ip={"ip": ip, "cc": cc or kv.get("loc"), "org": org, "colo": kv.get("colo")}, ip_ts=now)
    except Exception as e:
        LOG.warning("public ip: %s", e)
    return VPNSW["ip"]


def egress_counts(now, within=120):
    from .collect import EGRESS
    c = collections.Counter(e[5] for e in list(EGRESS.values()) if now - e[0] <= within)
    return {"n_tunnel": c["tunnel"], "n_direct": c["direct"], "n_local": c["local"]}


def flush_tunnel(db, now):
    cur = now // 60 * 60
    done = [x for x in TUN["minute"] if x["ts"] // 60 * 60 < cur]
    if not done:
        return
    TUN["minute"] = [x for x in TUN["minute"] if x["ts"] // 60 * 60 >= cur]
    by = collections.defaultdict(list)
    for x in done:
        by[x["ts"] // 60 * 60].append(x)
    for m, xs in by.items():
        avg = lambda k: (lambda v: sum(v) / len(v) if v else None)([x[k] for x in xs if x[k] is not None])
        ages = [x["hs_age"] for x in xs if x["hs_age"] is not None]
        db.run("INSERT OR REPLACE INTO tunnel_min VALUES(?,?,?,?,?,?,?,?,?)",
               (m, int(any(x["on"] for x in xs)), int(all(x["up"] for x in xs)), max(ages) if ages else None,
                avg("rx"), avg("tx"), round(avg("n_tunnel") or 0), round(avg("n_direct") or 0), round(avg("n_local") or 0)))


def tunnel_loop(db):
    """Every 20 s: handshake age and byte counters of the VPN, and how many live connections used it."""
    if not CFG["vpn"].get("enabled"):
        return
    STOP.wait(15)
    while not STOP.is_set():
        try:
            st = vpn_switch_status()
            if "error" not in st:
                now = st.get("now") or int(time.time())
                tr = st.get("transfer") or [0, 0]
                prev, rx, tx = TUN["prev"], None, None
                if prev and st["on"] and prev["on"] and now > prev["now"] and tr[0] >= prev["tr"][0] and tr[1] >= prev["tr"][1]:
                    dt = now - prev["now"]
                    rx, tx = (tr[0] - prev["tr"][0]) * 8 / dt, (tr[1] - prev["tr"][1]) * 8 / dt
                hs = st.get("handshake") or 0
                smp = {"ts": now, "on": st["on"], "up": st["up"], "hs_age": (now - hs) if (st["on"] and hs) else None,
                       "rx": rx, "tx": tx, **egress_counts(int(time.time()))}
                TUN["prev"] = {"now": now, "tr": tr, "on": st["on"]}
                TUN["last"] = {**smp, "dns": st.get("dns"), "endpoint": st.get("endpoint")}
                TUN["trace"].append(smp)
                TUN["minute"].append(smp)
                flush_tunnel(db, now)
        except Exception as e:
            LOG.warning("tunnel: %s", e)
        STOP.wait(20)


def vpn_expect():
    try:
        return set(json.loads(state.DBW.meta("vpn_expect", "[]")))
    except (ValueError, TypeError, AttributeError):
        return set()


def vpn_periods(r, t0, now):
    """[start, end, on] spans from the VPN switch events (state 1 = on), covering t0 to now."""
    st, start, out = 0, t0, []
    for ts, s in r.execute("SELECT ts, state FROM event WHERE kind = 'vpn' ORDER BY ts"):
        if ts <= t0:
            st = s
            continue
        if s != st:
            out.append([start, ts, st])
            start, st = ts, s
    out.append([start, now, st])
    return out


def _is_local(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return not a.is_global


def vpn_status():
    """Per device, right now: on a VPN, on a VPN with direct leaks, or not on a VPN."""
    from .capture import DPI_STATE
    from .collect import CONN_ACTIVE
    now = int(time.time())
    with reader() as r:
        who = ip_directory(r)
        rows = r.execute("SELECT src, dst, dport, proto FROM conn WHERE last >= ?", (now - 150,)).fetchall()
        dnsq = {x["client"]: x["n"] for x in r.execute("SELECT client, count(*) n FROM dns WHERE ts >= ? GROUP BY client",
                                                        (now - 600,))}
    skip = lambda dst, dport: _is_local(dst) or dport in (53, 123, 3478, 5353, 41641)
    live = collections.defaultdict(set)
    for (src, dst, dport, proto), t in list(CONN_ACTIVE.items()):
        if now - t <= 90 and not skip(dst, dport):
            live[src].add((dst, dport, proto))
    known = collections.defaultdict(set)
    for x in rows:
        if not skip(x["dst"], x["dport"]):
            known[x["src"]].add((x["dst"], x["dport"], x["proto"]))
    cap = {}
    for run in DPI_STATE["runs"]:
        if now - run["ts"] > 480:
            continue
        for f in run["flows"]:
            if f["lan"] not in cap and not f.get("inside"):
                cap[f["lan"]] = {"ts": run["ts"], "flows": [g for g in run["flows"] if g["lan"] == f["lan"] and not g.get("inside")]}
    tun = collections.defaultdict(list)
    for t in DPI_STATE["tunnels"].values():
        if (t["remote"], t["rport"], t["proto"]) in live.get(t["lan"], set()) or now - t["last"] < 400:
            tun[t["lan"]].append(t)
    expect = vpn_expect()
    out = []
    for ip in set(live) | set(tun) | set(known):
        d = who.get(ip, {})
        if d.get("vendor") == "infra":
            continue
        ts = [t for t in tun.get(ip, []) if t["provider"] != "Tailscale"]
        tdst = {(t["remote"], t["rport"], t["proto"]) for t in ts}
        c = cap.get(ip)
        leaks = []
        if c and ts:
            tot = sum(f["pkts"] for f in c["flows"]) or 1
            for f in c["flows"]:
                if not f["tunnel"] and f["pkts"] >= 3 and f["rport"] not in (53, 123, 1900, 3478, 5353, 41641) \
                        and f["label"] != "Tailscale disco" and not _is_local(f["remote"]) \
                        and not ipaddress.ip_address(f["remote"]).is_multicast:
                    leaks.append({"to": f.get("rname") or f["remote"], "org": f.get("org"), "label": f["label"],
                                  "share": round(100 * f["pkts"] / tot, 1)})
            direct, basis = len(leaks), "capture"
        else:
            direct, basis = len(live.get(ip, set()) - tdst), "live connections"
        if not live.get(ip) and not ts and not (c and c["flows"]):
            continue
        if ts and direct == 0:
            st = "vpn"
        elif ts and (basis == "capture" or direct > 2):
            st = "leak"
        elif ts:
            st = "vpn"
        else:
            st = "direct"
        out.append({"ip": ip, "mac": d.get("mac", ""), "name": d.get("name", ip), "vendor": d.get("vendor", ""), "status": st,
                    "tunnels": [{"provider": t["provider"], "label": t["label"], "remote": t["remote"], "rport": t["rport"],
                                 "proto": t["proto"], "since": t["first"], "guess": t["guess"], "org": t.get("org")} for t in ts],
                    "direct": direct, "leaks": leaks[:6], "basis": basis, "dns_10min": dnsq.get(ip, 0),
                    "expected": d.get("mac", "") in expect})
    order = {"leak": 0, "vpn": 2}
    out.sort(key=lambda x: (order.get(x["status"], 1 if x["expected"] else 3), x["name"]))
    return out
