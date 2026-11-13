# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security and VPN views: threat heuristics, packet-capture results, the ISP view, the VPN switch,
the tunnel, VPN cost, machine health, and the buttons that start captures, switches and tests.

Touches: reads the database and live state. The POST views start a capture (capture.py), a VPN
switch or a load test (heal.py, each behind its config switch), or save the list of devices that
must use a VPN (meta table).
"""
import bisect
import collections
import ipaddress
import json
import math
import os
import re
import threading
import time

from . import capture, checks, config, health, heal, state
from .classify import ip_directory, peer_names, router_self_names
from .collect import EGRESS
from .config import CFG
from .db import reader
from .dns import noise_clause
from .geo import geo_city, geo_lookup
from .state import claim, span
from .vpn import TUN, VPNSW, public_ip, vpn_expect, vpn_periods, vpn_status, vpn_switch_status

SEV_W = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
_DOH = {"set": None}


def doh_hosts():
    """Known DNS-over-HTTPS host names, from web/doh.js when present."""
    if _DOH["set"] is None:
        try:
            _DOH["set"] = set(re.findall(r'"([^"]+)"', open(os.path.join(config.ROOT, "web", "doh.js"), encoding="utf-8").read()))
        except OSError:
            _DOH["set"] = set()
    return _DOH["set"]


def is_doh(name):
    labels = str(name).lower().rstrip(".").split(".")
    hs = doh_hosts()
    return any(".".join(labels[i:]) in hs for i in range(len(labels) - 1))


def _global(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def api_threats(q):
    """Deterministic detections over the connection log, the DNS log and the device table, each mapped to an
    ATT&CK-style tactic. They flag patterns worth a human look, not verdicts."""
    sp = span(q)
    now = int(time.time())
    since = now - sp
    rn, fn = config.router_name(), config.filter_name()
    fenced = config.fenced_networks()
    lan = config.lan_networks()
    is_fenced = lambda ip: config.in_nets(ip, fenced)
    is_lan = lambda ip: config.in_nets(ip, lan)
    rself = config.router_addrs()
    dns_ok = rself | {"127.0.0.1", config.dns_server()}
    watch = set((CFG.get("threats") or {}).get("watch_countries") or [])
    allow = [(str(a.get("host_suffix") or "\0"), a.get("port")) for a in (CFG.get("threats") or {}).get("allow") or []]
    common_tcp = {80, 443, 853, 993, 995, 143, 465, 587, 5223, 5228, 5222, 8080, 8443, 22, 1194, 3478}
    common_udp = {443, 123, 53, 3478, 3479, 3480, 19302, 4500, 500, 51820, 41641, 1194, 5353}
    findings = []

    def add(sev, tactic, title, src, evidence, advice, count=1, first=None, last=None, **extra):
        findings.append({"sev": sev, "tactic": tactic, "title": title, "src": src, "evidence": evidence[:8],
                         "advice": advice, "count": count, "first": first, "last": last, **extra})

    with reader() as r:
        who = ip_directory(r)
        pn = peer_names(r)
        conns = r.execute("SELECT src, dst, proto, sport, dport, bytes_up, bytes_down, first, last, redir FROM conn "
                          "WHERE last >= ?", (since,)).fetchall()
        dns = r.execute(f"SELECT client, domain, count(*) n, sum(status='blocked') b, min(ts) f, max(ts) l FROM dns "
                        f"WHERE ts >= ? AND {noise_clause()} GROUP BY client, domain", (since,)).fetchall()
        newdev = r.execute("SELECT mac, ip, hostname, vendor, first_seen FROM device WHERE known = 0").fetchall()
        failing = r.execute("SELECT name, hard, output, since FROM check_state WHERE hard > 0").fetchall()
    per = lambda: collections.defaultdict(lambda: {"n": 0, "dst": collections.Counter(), "f": None, "l": None, "b_up": 0, "b_dn": 0})
    buckets = {k: per() for k in ("fenced_lan", "dns_out", "dns_caught", "dot_out", "admin_out", "tor", "http", "odd", "upnp", "watch")}
    fan = collections.defaultdict(set)
    flows = collections.defaultdict(lambda: [0, 0, None, None])
    for c in conns:
        ext = _global(c["dst"])
        src, dst, proto, dport = c["src"], c["dst"], c["proto"], c["dport"] or 0
        host = pn.get(dst) or ""

        def hit(k, key=src, label=None):
            b = buckets[k][key]
            b["n"] += 1
            b["dst"][label or f"{host or dst} {proto}/{dport}"] += 1
            b["f"] = min(b["f"] or c["first"], c["first"])
            b["l"] = max(b["l"] or c["last"], c["last"])
            b["b_up"] += c["bytes_up"] or 0
            b["b_dn"] += c["bytes_down"] or 0
        allowed = any(host.endswith(s) and dport == p for s, p in allow)
        if is_fenced(src) and is_lan(dst) and not is_fenced(dst) and dst not in dns_ok:
            hit("fenced_lan")
        if ext and dport == 53 and src not in dns_ok:
            hit("dns_out" if c["redir"] == 0 else "dns_caught")
        if ext and dport == 853 and src not in dns_ok:
            hit("dot_out")
        if ext and proto == "tcp" and dport in (23, 135, 139, 445, 3389, 5900) and not allowed:
            hit("admin_out")
        if ext and dport in (9001, 9030, 9050, 9150):
            hit("tor")
        if ext and proto == "tcp" and dport == 80:
            hit("http")
        if ext and not allowed and ((proto == "tcp" and dport not in common_tcp) or
                                    (proto == "udp" and dport not in common_udp and c["sport"] != 41641 and dport < 49152)):
            hit("odd")
        if proto == "udp" and dport in (1900, 5351) and dst in rself:
            hit("upnp")
        if ext:
            cc = geo_lookup(dst)[0]
            if cc in watch:
                hit("watch", key=(src, proto == "icmp"), label=f"{host or dst} ({cc}) {proto}{'' if proto == 'icmp' else '/' + str(dport)}")
            f = flows[(src, dst)]
            f[0] += c["bytes_up"] or 0
            f[1] += c["bytes_down"] or 0
            f[2] = min(f[2] or c["first"], c["first"])
            f[3] = max(f[3] or c["last"], c["last"])
        elif is_lan(dst) and is_lan(src):
            fan[(src, (c["first"] or 0) // 600)].add(f"{dst}:{dport}")
    ev = lambda b: [f"{k} ×{v}" for k, v in b["dst"].most_common(8)]
    for src, b in buckets["fenced_lan"].items():
        add("high", "Lateral movement", "Device in a fenced zone reached into the main network", src, ev(b),
            f"Fenced zones should not reach other devices. Check the zone rules on {rn}, and what this device was trying to do.",
            b["n"], b["f"], b["l"])
    for src, b in buckets["dns_out"].items():
        add("high", "Defense evasion", f"DNS sent straight to the internet, around the {fn}", src, ev(b),
            f"Force DNS through {rn} with a firewall redirect of port 53.", b["n"], b["f"], b["l"])
    for src, b in buckets["dns_caught"].items():
        add("low", "Defense evasion", f"Tried outside DNS; {rn} caught it and answered itself", src, ev(b),
            f"Contained: {rn} redirects every port-53 request to its own resolver. Hard-coded DNS like this is common on TV sticks and phones.",
            b["n"], b["f"], b["l"], contained=True)
    for src, b in buckets["dot_out"].items():
        add("medium", "Defense evasion", f"Encrypted DNS (DoT, port 853) around the {fn}", src, ev(b),
            f"Block outbound port 853 from clients, so only {rn} resolves names.", b["n"], b["f"], b["l"])
    for src, b in buckets["admin_out"].items():
        add("high", "Command and control", "Remote-admin or file-sharing protocol to the internet", src, ev(b),
            "SMB, RDP, VNC or Telnet should never leave the site. Find the app responsible and block it.", b["n"], b["f"], b["l"])
    for src, b in buckets["tor"].items():
        add("high", "Command and control", "Tor-style ports to the internet", src, ev(b),
            "Tor is sometimes used by malware to hide its control channel. Check whether Tor is installed on purpose.",
            b["n"], b["f"], b["l"])
    for (src, icmp), b in buckets["watch"].items():
        add("low" if icmp else "medium", "Command and control",
            "Ping to a watch-list country" if icmp else "Connections to a watch-list country", src, ev(b),
            "Often harmless (a CDN or app), but worth knowing. The watch list is threats.watch_countries in config.json.",
            b["n"], b["f"], b["l"])
    for src, b in buckets["odd"].items():
        add("low", "Command and control", "Unusual outbound ports", src, ev(b),
            "Most traffic uses a handful of ports. Unusual ones can be games or apps, or a hidden channel.", b["n"], b["f"], b["l"])
    for src, b in buckets["http"].items():
        add("low", "Credential access", "Unencrypted web (HTTP) to the internet", src, ev(b),
            "Anything sent over plain HTTP can be read or changed on the way. Usually software update checks or captive-portal tests.",
            b["n"], b["f"], b["l"])
    for src, b in buckets["upnp"].items():
        add("info", "Persistence", f"Asked {rn} to open inbound ports (UPnP or NAT-PMP)", src, ev(b),
            f"Apps like Tailscale do this to connect faster. If you do not need it, switch UPnP off on {rn}.", b["n"], b["f"], b["l"])
    for (src, dst), (up, dn, f, l) in flows.items():
        if up > 25e6 and up > 3 * max(dn, 1):
            add("high" if up > 250e6 else "medium", "Exfiltration", "Large one-way upload to a single outside address", src,
                [f"{pn.get(dst) or dst}: {up / 1e6:.0f} MB up, {dn / 1e6:.1f} MB down"],
                "Check it is a backup or upload you expect.", 1, f, l, dst=dst)
    scans = collections.defaultdict(int)
    for (src, _), targets in fan.items():
        scans[src] = max(scans[src], len(targets))
    for src, n in scans.items():
        if n >= 25:
            add("medium", "Discovery", "Many local devices and ports contacted in ten minutes", src,
                [f"{n} different device:port pairs in one ten-minute window"],
                "Could be a network scanner, a printer search or malware looking around. Check the device.", n)
    per_client = collections.defaultdict(lambda: {"doh": collections.Counter(), "ddr": 0, "n": 0, "b": 0, "f": None, "l": None,
                                                  "sneak_b": 0, "sneak_n": 0})
    for d in dns:
        pc = per_client[d["client"]]
        pc["n"] += d["n"]
        pc["b"] += d["b"] or 0
        pc["f"] = min(pc["f"] or d["f"], d["f"])
        pc["l"] = max(pc["l"] or d["l"], d["l"])
        if d["domain"] == "_dns.resolver.arpa":
            pc["ddr"] += d["n"]
            pc["sneak_n"] += d["n"]
            pc["sneak_b"] += d["b"] or 0
        elif d["domain"] == "use-application-dns.net" or (is_doh(d["domain"]) and not d["domain"].startswith("mask")):
            pc["doh"][d["domain"]] += d["n"]
            pc["sneak_n"] += d["n"]
            pc["sneak_b"] += d["b"] or 0
    for cl, pc in per_client.items():
        if cl in router_self_names():
            continue
        if pc["doh"] or pc["ddr"]:
            evd = [f"{k} ×{v}" for k, v in pc["doh"].most_common(6)] + ([f"_dns.resolver.arpa ×{pc['ddr']}"] if pc["ddr"] else [])
            add("medium" if sum(pc["doh"].values()) > 10 else "low", "Defense evasion", "Tried to switch to encrypted DNS (DoH or DDR)",
                cl, evd, f"When the {fn} blocks these names, the device falls back to normal DNS. Keep a DoH blocklist current.",
                sum(pc["doh"].values()) + pc["ddr"], pc["f"], pc["l"], contained=pc["sneak_b"] >= pc["sneak_n"] * 0.95)
        if pc["n"] >= 200 and pc["b"] / pc["n"] > 0.4:
            add("low", "Collection", "Adware-like behaviour: most lookups are ads and trackers", cl,
                [f"{pc['b']:,} of {pc['n']:,} lookups blocked ({100 * pc['b'] / pc['n']:.0f}%)"],
                "Look for ad-heavy apps on this device and remove the ones you do not use.", pc["b"], pc["f"], pc["l"])
    for d in newdev:
        add("medium", "Initial access", "A device joined that you have not reviewed", d["ip"] or d["mac"],
            [f"{d['hostname'] or 'no name'} · {d['vendor'] or 'unknown maker'} · {d['mac']}"],
            "Confirm you know it on the Devices page, then mark it known.", 1, d["first_seen"], d["first_seen"], mac=d["mac"])
    titles = checks.titles()
    for c in failing:
        add("medium" if c["hard"] >= 2 else "low", "Impact", f"Check failing: {titles.get(c['name'], c['name'])}", "network",
            [c["output"] or ""], "See the Checks page.", 1, c["since"], now)
    for f in findings:
        f["device"] = who.get(f["src"], {"name": f["src"]})["name"] if f["src"] != "network" else "The network"
        f.setdefault("mac", who.get(f["src"], {}).get("mac", ""))
        f["vendor"] = who.get(f["src"], {}).get("vendor", "")
        f["zone"] = "iot" if is_fenced(str(f["src"])) else "lan"
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order[f["sev"]], -f["count"]))
    score = round(100 * (1 - math.exp(-sum(SEV_W[f["sev"]] for f in findings) / 90)))
    return {"now": now, "span": sp, "score": score, "findings": findings,
            "devices": [{"ip": ip, **v} for ip, v in who.items() if v.get("vendor") != "infra"]}


# ---------------------------------------------------------------- captures and VPN


def api_dpi(q):
    D = capture.DPI_STATE
    return {"now": int(time.time()), "busy": D["busy"], "last": D["last"], "error": D["error"],
            "every": CFG["dpi"].get("every_s", 300), "runs": list(D["runs"])[:4], "tunnels": list(D["tunnels"].values()),
            "vpn": vpn_status()}


def api_vpn(q):
    return {"now": int(time.time()), "vpn": vpn_status(), "last_capture": capture.DPI_STATE["last"],
            "busy": capture.DPI_STATE["busy"]}


def api_dpi_capture(q, body):
    iface = body.get("iface") or capture.ifaces()[0]
    secs = int(body.get("secs", 12))
    if iface not in set(config.bridges()) | {CFG["router"]["wan_iface"]} | set(capture.ifaces()) or not 5 <= secs <= 30:
        return {"ok": False, "error": "bad request"}
    if not CFG["actions"].get("captures", True):
        return {"ok": False, "error": "captures are turned off (actions.captures in config.json)"}
    if not claim(capture.DPI_STATE):
        return {"ok": False, "error": "a capture is already running"}
    threading.Thread(target=capture.dpi_run, args=(iface, secs, True), daemon=True).start()
    return {"ok": True, "started": int(time.time()), "secs": secs}


def api_vpn_expect(q, body):
    mac, on = str(body.get("mac", ""))[:17], bool(body.get("on"))
    cur = vpn_expect()
    (cur.add if on else cur.discard)(mac)
    state.DBW.set_meta("vpn_expect", json.dumps(sorted(cur)))
    return {"ok": True, "expect": sorted(cur)}


def api_isp(q):
    S_ = capture.ISP_STATE
    if not S_["by_vpn"]:
        try:
            S_["by_vpn"] = json.loads(state.DBW.meta("isp_by_vpn", "{}"))
        except (ValueError, TypeError):
            pass
    now = int(time.time())
    with reader() as r:
        wan = sum(1 for (d,) in r.execute("SELECT dst FROM conn WHERE last >= ?", (now - 600,)) if _global(d))
    d = CFG["dns"]
    path = d.get("path_text") or (f"Devices ask {config.router_name()}; it answers from its cache or asks "
                                  f"{d.get('upstream_label') or 'its upstream resolver'}.")
    return {"now": now, "busy": S_["busy"], "error": S_["error"], "run": S_["run"], "active_conns": wan,
            "by_vpn": S_["by_vpn"], "dns_path": path}


def api_isp_capture(q, body):
    secs = int(body.get("secs", 20))
    if not 5 <= secs <= 30:
        return {"ok": False, "error": "bad request"}
    if not CFG["actions"].get("captures", True):
        return {"ok": False, "error": "captures are turned off (actions.captures in config.json)"}
    if not claim(capture.ISP_STATE):
        return {"ok": False, "error": "a look is already running"}
    threading.Thread(target=capture.isp_run, args=(secs, True), daemon=True).start()
    return {"ok": True, "started": int(time.time()), "secs": secs}


def api_vpnswitch(q):
    v = CFG["vpn"]
    on = bool(v.get("enabled"))
    return {"now": int(time.time()), "busy": VPNSW["busy"], "switch": vpn_switch_status() if on else {"error": "no VPN configured"},
            "ip": public_ip() if on else None, "last": VPNSW["last"], "profile": v.get("profile") or v.get("label") or "VPN",
            "enabled": on, "can_switch": on and bool(CFG["actions"].get("vpn_switch"))}


def api_vpnswitch_set(q, body):
    return heal.start_vpn_switch(bool(body.get("on")))


def api_bloattest(q, body):
    return heal.start_load_test()


def api_tunnel(q):
    sp = span(q, "6h")
    now = int(time.time())
    rself = config.router_addrs()
    with reader() as r:
        by_ip = ip_directory(r)
        pn = peer_names(r)
        hist = [list(x) for x in r.execute(
            "SELECT ts, vpn_on, vpn_up, hs_age, rx, tx, n_tunnel, n_direct, n_local FROM tunnel_min WHERE ts >= ? ORDER BY ts",
            (now - sp,))]
    devs, around, home = {}, [], collections.Counter()
    for t, src, dst, dport, proto, eg in [e for e in list(EGRESS.values()) if now - e[0] <= 180]:
        d = by_ip.get(src) or {"mac": None, "name": src, "vendor": ""}
        x = devs.setdefault(d.get("mac") or src, {"mac": d.get("mac"), "name": d["name"], "vendor": d.get("vendor") or "",
                                                  "ip": src, "tunnel": 0, "direct": 0, "local": 0})
        x[eg] += 1
        if eg == "direct":
            cc, asn, org = geo_lookup(dst)
            around.append({"device": d["name"], "mac": d.get("mac"), "dst": dst, "dport": dport, "proto": proto,
                           "name": pn.get(dst), "org": org, "cc": cc, "last": t})
        elif eg == "local":
            home[(d["name"], d.get("mac"), proto, dport, dst)] += 1
    last = TUN["last"] or {}
    ep = last.get("endpoint") or ""
    eip = ep.rsplit(":", 1)[0] if ":" in ep else ""
    cc, asn, org = geo_lookup(eip) if eip else (None, None, None)
    dst_name = lambda ip: (by_ip.get(ip) or {}).get("name") or (config.router_name() if ip in rself else pn.get(ip) or ip)
    return {"now": now, "span": sp, "status": last, "exit": public_ip() if CFG["vpn"].get("enabled") else None,
            "endpoint": {"ip": eip, "port": ep.rsplit(":", 1)[-1] if eip else None, "cc": cc, "org": org,
                         "place": geo_city(eip) if eip else None},
            "devices": sorted(devs.values(), key=lambda d: -(d["tunnel"] + d["direct"] + d["local"])),
            "around": sorted(around, key=lambda a: -a["last"])[:60],
            "home": [{"device": k[0], "mac": k[1], "proto": k[2], "dport": k[3], "dst": k[4], "n": n, "dst_name": dst_name(k[4])}
                     for k, n in home.most_common(40)],
            "history": hist, "trace": list(TUN["trace"]) if sp <= 3600 else []}


def qstats(v):
    if not v:
        return None
    v = sorted(v)
    q = lambda f: v[min(len(v) - 1, int(f * (len(v) - 1) + 0.5))]
    return {"n": len(v), "p10": q(.1), "p25": q(.25), "med": q(.5), "p75": q(.75), "p90": q(.9), "mean": sum(v) / len(v)}


def api_vpncost(q):
    """Delay and loss to each latency target with the VPN off against on. Targets inside the site are the
    control: the tunnel should not change them."""
    sp = span(q)
    now = int(time.time())
    t0 = now - sp
    local = config.local_target_names()
    with reader() as r:
        periods = vpn_periods(r, t0, now)
        tmin = {x[0]: x[1] for x in r.execute("SELECT ts, vpn_on FROM tunnel_min WHERE ts >= ?", (t0,))}
        lat = r.execute("SELECT ts, target, rtt_med, loss FROM latency_min WHERE ts >= ? ORDER BY ts", (t0,)).fetchall()
        vit = r.execute("SELECT ts, down_max, up_max FROM vitals_min WHERE ts >= ?", (t0,)).fetchall()
    starts = [p[0] for p in periods]

    def on_at(ts):
        m = ts // 60 * 60
        if m in tmin:
            return tmin[m]
        return periods[max(0, bisect.bisect_right(starts, ts) - 1)][2]
    g = collections.defaultdict(lambda: {"off": [], "on": [], "loss_off": [], "loss_on": []})
    series = []
    for ts, tg, rtt, loss in lat:
        k = "on" if on_at(ts) else "off"
        if rtt is not None:
            g[tg][k].append(rtt)
            series.append([ts, tg, round(rtt, 2)])
        if loss is not None:
            g[tg]["loss_" + k].append(loss)
    thin = lambda v, n=500: v if len(v) <= n else v[::max(1, len(v) // n)]
    targets = {tg: {"off": qstats(x["off"]), "on": qstats(x["on"]), "samples_off": thin(x["off"]), "samples_on": thin(x["on"]),
                    "loss_off": (sum(x["loss_off"]) / len(x["loss_off"])) if x["loss_off"] else None,
                    "loss_on": (sum(x["loss_on"]) / len(x["loss_on"])) if x["loss_on"] else None,
                    "local": tg in local} for tg, x in g.items()}
    peak = {"off": [], "on": []}
    for ts, dmax, umax in vit:
        peak["on" if on_at(ts) else "off"].append(dmax or 0)
    on_secs = sum(min(b, now) - max(a, t0) for a, b, st in periods if st)
    return {"now": now, "span": sp, "periods": periods, "targets": targets, "series": thin(series, 3000),
            "peak_down": {k: (sorted(v)[int(.95 * (len(v) - 1))] if v else None) for k, v in peak.items()},
            "on_share": on_secs / sp if sp else 0}


def api_health(q):
    return health.health_view(span(q))
