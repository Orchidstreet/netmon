# SPDX-License-Identifier: AGPL-3.0-or-later
"""Traffic analysis views: where traffic goes, which ports and timers it uses, Wi-Fi, encryption,
daily rhythm, the companies behind DNS names, DNS speed, ping pulse and bufferbloat.

Touches: reads the database (read-only connections), live state and the geography tables.
Writes nothing. Each function takes the query dict and returns a JSON-ready dict.
"""
import bisect
import collections
import ipaddress
import json
import math
import statistics
import time

from . import config
from .classify import TAILNET, company_map, company_of, device_names, dns_clients, ip_directory, named, peer_names
from .collect import BLOAT, cake_devs
from .config import CFG
from .db import reader
from .dns import noise_clause
from .geo import GEO, geo_city, geo_lookup
from .state import S, span
from .vpn import vpn_periods


def _global(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def api_geo(q):
    """Every outside address in the connection log, with country, owner and name."""
    sp = span(q)
    now = int(time.time())
    with reader() as r:
        names = device_names(r)
        ip2mac = {v["ip"]: m for m, v in names.items() if v["ip"]}
        for m, l in list(S.links.items()):
            if l.get("ip"):
                ip2mac.setdefault(l["ip"], m)
        pn = peer_names(r)
        rows = r.execute("SELECT src, dst, dport, proto, sum(bytes_down) bd, sum(bytes_up) bu, count(*) n, "
                         "min(first) f, max(last) l FROM conn WHERE last >= ? GROUP BY src, dst, dport, proto",
                         (now - sp,)).fetchall()
    dests = {}
    for x in rows:
        if not _global(x["dst"]):
            continue
        d = dests.get(x["dst"])
        if not d:
            cc, asn, org = geo_lookup(x["dst"])
            place = geo_city(x["dst"])
            if place and place["cc"] and place["cc"] != "ZZ":
                cc = place["cc"]
            d = dests[x["dst"]] = {"ip": x["dst"], "cc": cc, "asn": asn, "org": org, "place": place,
                                   "host": pn.get(x["dst"]) or "", "ports": [], "down": 0, "up": 0, "conns": 0,
                                   "macs": {}, "first": x["f"], "last": x["l"]}
        d["down"] += x["bd"] or 0
        d["up"] += x["bu"] or 0
        d["conns"] += x["n"]
        d["first"], d["last"] = min(d["first"], x["f"]), max(d["last"], x["l"])
        port = f'{x["proto"]}/{x["dport"]}'
        if port not in d["ports"] and len(d["ports"]) < 4:
            d["ports"].append(port)
        mac = ip2mac.get(x["src"], x["src"])
        d["macs"][mac] = d["macs"].get(mac, 0) + (x["bd"] or 0) + (x["bu"] or 0)
    devs = {}
    for d in dests.values():
        for m in d["macs"]:
            if m not in devs:
                devs[m] = {"mac": m, **{k: v for k, v in named(names, m).items() if k in ("name", "ip", "vendor")}}
    return {"ready": GEO.get("ready", False), "error": GEO.get("error"), "source": GEO.get("source"),
            "city": bool(GEO.get("city")), "home": {"cc": CFG["site"].get("cc", ""), "label": CFG["site"].get("name", "")},
            "now": now, "span": sp, "dests": sorted(dests.values(), key=lambda d: -(d["down"] + d["up"])),
            "devices": list(devs.values())}


def api_privacy(q):
    """DNS behaviour per client: volume, blocked share, and the names behind it."""
    sp = span(q)
    now = int(time.time())
    noise = noise_clause()
    with reader() as r:
        who = ip_directory(r)
        names = dns_clients(r)
        w = (now - sp,)
        clients = {x["client"]: dict(x) for x in r.execute(
            "SELECT client, count(*) n, sum(status='blocked') b, sum(status='cached') c, sum(status='forwarded') f, "
            f"min(ts) first, max(ts) last FROM dns WHERE ts >= ? AND {noise} GROUP BY client", w)}
        doms = collections.defaultdict(list)
        for x in r.execute(f"SELECT client, domain, count(*) n, sum(status='blocked') b FROM dns WHERE ts >= ? AND {noise} "
                           "GROUP BY client, domain ORDER BY n DESC", w):
            if len(doms[x["client"]]) < 80 or x["b"]:
                doms[x["client"]].append([x["domain"], x["n"], x["b"]])
        hours = collections.defaultdict(dict)
        for x in r.execute(f"SELECT client, ts/3600*3600 t, count(*) n, sum(status='blocked') b FROM dns WHERE ts >= ? "
                           f"AND {noise} GROUP BY client, t", w):
            hours[x["client"]][x["t"]] = [x["n"], x["b"]]
    out = []
    for ip, c in clients.items():
        d = who.get(ip)
        base = {"mac": d["mac"], "name": d["name"], "vendor": d["vendor"]} if d and d["vendor"] != "infra" else \
            {"mac": "", "name": names.get(ip, ip), "vendor": "infra" if ip in names else ""}
        out.append({**c, "ip": ip, **base, "domains": doms[ip][:160],
                    "hours": sorted([t, *v] for t, v in hours[ip].items())})
    out.sort(key=lambda c: -c["n"])
    return {"now": now, "span": sp, "clients": out}


def api_ports(q):
    """Every service (protocol and port) in the connection log, with who used it and where to."""
    sp = span(q)
    now = int(time.time())
    with reader() as r:
        who = ip_directory(r)
        pn = peer_names(r)
        rows = r.execute("SELECT proto, CASE WHEN proto = 'udp' AND sport = 41641 THEN 41641 ELSE dport END dport, src, dst, "
                         "count(*) n, sum(bytes_up + bytes_down) b FROM conn WHERE last >= ? GROUP BY 1, 2, src, dst",
                         (now - sp,)).fetchall()
    ports = {}
    for x in rows:
        if x["proto"] not in ("tcp", "udp"):
            continue
        p = ports.setdefault(f'{x["proto"]}/{x["dport"]}', {"proto": x["proto"], "port": x["dport"], "conns": 0, "bytes": 0,
                                                            "devices": {}, "dests": set(), "internal": 0, "external": 0,
                                                            "hosts": {}})
        p["conns"] += x["n"]
        p["bytes"] += x["b"] or 0
        dev = who.get(x["src"], {"name": x["src"]})["name"]
        p["devices"][dev] = p["devices"].get(dev, 0) + x["n"]
        p["dests"].add(x["dst"])
        p["external" if _global(x["dst"]) else "internal"] += x["n"]
        h = pn.get(x["dst"]) or who.get(x["dst"], {}).get("name") or x["dst"]
        p["hosts"][h] = p["hosts"].get(h, 0) + x["n"]
    out = []
    for p in ports.values():
        p["dests"] = len(p["dests"])
        p["hosts"] = sorted(p["hosts"].items(), key=lambda kv: -kv[1])[:6]
        p["devices"] = sorted(p["devices"].items(), key=lambda kv: -kv[1])[:8]
        out.append(p)
    out.sort(key=lambda p: -p["conns"])
    return {"now": now, "span": sp, "ports": out}


def api_beacons(q):
    """Regularity of repeated connections from one device to one destination: timers stand out."""
    sp = span(q)
    now = int(time.time())
    with reader() as r:
        who = ip_directory(r)
        pn = peer_names(r)
        rows = r.execute("SELECT src, dst, proto, dport, first, bytes_up + bytes_down b FROM conn WHERE first >= ? "
                         "ORDER BY src, dst, proto, dport, first", (now - sp,)).fetchall()
    groups = collections.defaultdict(list)
    for x in rows:
        groups[(x["src"], x["dst"], x["proto"], x["dport"])].append((x["first"], x["b"] or 0))
    out = []
    for (src, dst, proto, dport), ev in groups.items():
        ts = sorted({t for t, _ in ev})
        if len(ts) < 5:
            continue
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b > a]
        if len(gaps) < 4:
            continue
        mean, med, sd = statistics.mean(gaps), statistics.median(gaps), statistics.pstdev(gaps)
        cv = sd / mean if mean else 9
        tol = max(5, med * 0.15)
        regular = sum(1 for g in gaps if abs(g - med) <= tol) / len(gaps)
        glob_ = _global(dst)
        cc, asn, org = geo_lookup(dst) if glob_ else (None, None, None)
        out.append({"src": src, "device": who.get(src, {"name": src})["name"], "mac": who.get(src, {}).get("mac", ""),
                    "dst": dst, "host": pn.get(dst) or who.get(dst, {}).get("name") or "", "proto": proto, "port": dport,
                    "n": len(ts), "median": med, "mean": round(mean, 1), "cv": round(cv, 3), "regular": round(regular, 3),
                    "bytes": sum(b for _, b in ev), "first": ts[0], "last": ts[-1], "external": glob_, "cc": cc, "org": org,
                    "times": ts[-120:]})
    out.sort(key=lambda b: -(b["regular"] * math.log(1 + b["n"])))
    return {"now": now, "span": sp, "pairs": out[:300]}


def api_air(q):
    """Wi-Fi now and over time: every client's band, signal and link rate."""
    sp = span(q, "6h")
    now = int(time.time())
    with reader() as r:
        names = device_names(r)
        hist = collections.defaultdict(list)
        for x in r.execute("SELECT ts, mac, band, signal, rate FROM link_min WHERE ts >= ? AND kind = 'wifi' ORDER BY ts",
                           (now - sp,)):
            hist[x["mac"]].append([x["ts"], x["signal"], x["rate"], x["band"]])
    pick = lambda m: {k: v for k, v in named(names, m).items() if k in ("name", "vendor")}
    clients = [{"mac": m, **pick(m), **l, "history": hist.get(m, [])} for m, l in list(S.links.items()) if l.get("kind") == "wifi"]
    gone = [{"mac": m, **pick(m), "history": h} for m, h in hist.items() if m not in S.links]
    return {"now": now, "span": sp, "clients": clients, "gone": gone, "wifi_clients": (S.vitals or {}).get("wifi_clients")}


# ---------------------------------------------------------------- encryption

PROTO_CLASS = {
    "enc": {"HTTP/S", "QUIC", "TLS", "SSH", "WireGuard", "Tailscale", "Apple/Push", "IMAP/S", "POP3/S", "SMTP/S", "XMPP",
            "HTTP/Connect", "IPSEC", "OpenVPN", "DoT", "DoH", "Kerberos", "RDP", "Signal", "WhatsApp", "Telegram", "FaceTime",
            "Spotify", "Netflix", "Zoom", "Teams", "Tor", "SSL", "HTTPS", "iMessage"},
    "plain": {"HTTP", "FTP/C", "FTP/D", "FTP", "Telnet", "POP3", "IMAP", "SMTP", "DNS", "NETBIOS", "SMBv1", "SMBv23", "SNMP",
              "Whois/DAS", "TFTP", "Syslog", "mDNS", "SSDP", "DHCP", "LLMNR", "UPnP", "Cassandra", "MySQL", "PostgreSQL", "Redis",
              "RTSP", "RTP", "SIP", "IRC", "VNC", "LDAP", "NFS", "HTTP/Proxy"},
    "house": {"ICMP", "NTP", "Roughtime", "STUN", "OOKLA", "IGMP", "ARP", "ICMPv6"},
}
PLAIN_PORTS = {80: "Web (HTTP)", 8080: "Web (HTTP, port 8080)", 8000: "Web (HTTP, port 8000)", 8008: "Web (HTTP, port 8008)",
               21: "File transfer (FTP)", 23: "Telnet", 25: "Mail (SMTP)", 110: "Mail (POP3)", 143: "Mail (IMAP)",
               139: "Windows file sharing (old)", 445: "Windows file sharing (SMB)", 5900: "Screen sharing (VNC)", 161: "SNMP"}
SERVICE_PORTS = {**PLAIN_PORTS, 443: "HTTPS", 22: "SSH", 993: "Mail (IMAPS)", 853: "DNS over TLS", 3389: "Remote desktop",
                 548: "Apple file sharing", 5000: "NAS web page", 5001: "NAS web page", 9100: "Printer",
                 631: "Printer (IPP)", 8443: "HTTPS (port 8443)", 5223: "Apple push", 5222: "Chat (XMPP)",
                 7000: "AirPlay (speaker or TV)", 62078: "iPhone sync", 8009: "Chromecast"}


def crypto_why():
    return {"enc": "Encrypted: only the two ends can read it", "plain": "Plain text: readable by anyone on the path",
            "house": "Housekeeping: pings, clock, call setup and speed tests; nothing private inside",
            "unk": f"Not recognised by {config.router_name()}"}


def proto_class(name):
    for k, v in PROTO_CLASS.items():
        if name in v:
            return k
    n = (name or "").lower()
    return "enc" if any(x in n for x in ("tls", "https", "quic", "ssh", "/s")) else "unk"


def ip_scope(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "internet"
    if a in TAILNET:
        return "tailnet"
    if a.is_global:
        return "internet"
    nets = config.lan_networks()
    for extra in (CFG["uplink"].get("cidr"), CFG["uplink"].get("ip")):
        if extra:
            try:
                nets.append(ipaddress.ip_network(extra, strict=False))
            except ValueError:
                pass
    return "home" if any(a in n for n in nets) else "elsewhere"


def plain_reason(host, port, dst):
    h = (host or "").lower()
    sc = ip_scope(dst)
    if sc == "tailnet":
        return "ok", "Inside Tailscale, which encrypts it on the way"
    if sc == "home":
        return "ok", "Stays inside the site"
    if sc == "elsewhere":
        return "look", "A private address that is not on this site's networks"
    for a in (CFG.get("threats") or {}).get("allow") or []:
        if h.endswith(str(a.get("host_suffix") or "\0")) and port == a.get("port"):
            return "skip", a.get("why") or "Allowed in config.json"
    if "tailscale.com" in h and "derp" in h:
        return "ok", "Tailscale relay check: the traffic it carries is encrypted by Tailscale"
    if any(x in h for x in ("speedtest", "ookla", ".lg.", "-lg", "lg1.", "lg.", "pingless", "fast.com", "wsqm")):
        return "ok", "Speed test: only filler data"
    if any(x in h for x in ("gvt1.com", "edgedl", "swcdn", "download", "update", "windowsupdate", "dl.google", "delivery.mp.microsoft")):
        return "ok", "Software download: signed and checked before it installs"
    if any(x in h for x in ("connectivitycheck", "captive", "msftconnecttest", "gstatic.com", "detectportal", "nmcheck",
                            "tizen.org", "samsung.com", "mozilla", "apple.com/library/test")):
        return "ok", "Online check: asks for an empty page to see if the internet works"
    if any(x in h for x in ("ocsp", "crl.", "pki.", "digicert", "cdp1.", "letsencrypt", "sectigo", "globalsign")):
        return "ok", "Certificate check: public and signed"
    if "safebrowsing" in h or "aaplimg" in h:
        return "ok", "Safe-browsing lookup: sends only scrambled fragments"
    if port == 80:
        return "look", "A web address asked for without https. Most sites move it to https at once; worth a look"
    return "look", "Not explained: worth a look"


def api_crypto(q):
    now = int(time.time())
    sp = span(q)
    t0 = now - sp
    with reader() as r:
        names = device_names(r)
        ipdir = ip_directory(r)
        peers = peer_names(r)
        devs, protos = {}, collections.Counter()
        for mac, pid, dn, up in r.execute("SELECT mac, proto, sum(down), sum(up) FROM app_15s WHERE ts >= ? GROUP BY mac, proto", (t0,)):
            pname = S.protos.get(pid) or f"Protocol {pid}"
            cls = proto_class(pname)
            n = (named(names, mac)["name"] or "").strip() or f"Unnamed device ({mac[-5:]})"
            d = devs.setdefault(n, {"name": n, "macs": set(), "enc": 0, "plain": 0, "house": 0, "unk": 0,
                                    "protos": collections.Counter()})
            d["macs"].add(mac)
            b = (dn or 0) + (up or 0)
            d[cls] += b
            d["protos"][pname] += b
            protos[(pname, cls)] += b
        out_devs = []
        for d in devs.values():
            tot = d["enc"] + d["plain"] + d["house"] + d["unk"]
            if tot >= 50_000:
                out_devs.append({"name": d["name"], "macs": sorted(d["macs"]), "enc": d["enc"], "plain": d["plain"],
                                 "house": d["house"], "unk": d["unk"], "total": tot,
                                 "protos": [[p, proto_class(p), b] for p, b in d["protos"].most_common(8)]})
        out_devs.sort(key=lambda d: -d["total"])
        plain, ports = {}, tuple(PLAIN_PORTS)
        for src, dst, dport, n, f, l in r.execute(
                f"SELECT src, dst, dport, count(*), min(first), max(last) FROM conn WHERE last >= ? AND proto='tcp' "
                f"AND dport IN ({','.join('?' * len(ports))}) GROUP BY src, dst, dport", (t0, *ports)):
            host = peers.get(dst, "")
            verdict, why = plain_reason(host, dport, dst)
            if verdict == "skip":
                continue
            dev = ipdir.get(src, {}).get("name", src)
            e = plain.setdefault((dev, host or dst, dport), {"device": dev, "host": host, "ip": dst, "port": dport,
                                                            "service": PLAIN_PORTS[dport], "scope": ip_scope(dst),
                                                            "verdict": verdict, "why": why, "conns": 0, "first": f, "last": l})
            e["conns"] += n
            e["first"], e["last"] = min(e["first"], f), max(e["last"], l)
        knock = {}
        for src, dst, dport, n, f, l in r.execute(
                "SELECT src, dst, dport, count(*), min(first), max(last) FROM conn WHERE last >= ? AND proto='tcp' AND "
                "state='SYN_SENT' GROUP BY src, dst, dport HAVING count(*) >= 3 ORDER BY count(*) DESC LIMIT 60", (t0,)):
            e = knock.setdefault((src, dst), {"device": ipdir.get(src, {}).get("name", src), "host": peers.get(dst, ""),
                                              "ip": dst, "port": dport, "services": [], "scope": ip_scope(dst), "tries": 0,
                                              "first": f, "last": l})
            e["services"].append(SERVICE_PORTS.get(dport, f"port {dport}"))
            e["tries"] += n
            e["first"], e["last"] = min(e["first"], f), max(e["last"], l)
    tot = collections.Counter()
    for d in out_devs:
        for k in ("enc", "plain", "house", "unk"):
            tot[k] += d[k]
    return {"now": now, "span": sp, "why": crypto_why(), "totals": tot, "devices": out_devs[:24],
            "protos": [[p, c, b] for (p, c), b in protos.most_common(24)],
            "plain": sorted(plain.values(), key=lambda e: (e["verdict"] != "look", -e["conns"])),
            "knock": sorted(knock.values(), key=lambda e: -e["tries"])[:30]}


def api_rhythm(q):
    """The last 24 hours in 10-minute steps: link speed, DNS lookups, devices awake, and each busy device's hours."""
    now = int(time.time())
    B = 600
    t0 = (now - 86400) // B * B + B
    n = (now - t0) // B + 1
    idx = lambda ts: (ts - t0) // B
    down, up, dns, cnt = [0.0] * n, [0.0] * n, [0] * n, [0] * n
    awake = [set() for _ in range(n)]
    with reader() as r:
        names = device_names(r)
        for ts, dn, u in r.execute("SELECT ts, down, up FROM vitals_min WHERE ts >= ?", (t0,)):
            i = idx(ts)
            if 0 <= i < n:
                down[i] += dn or 0
                up[i] += u or 0
                cnt[i] += 1
        for ts, c in r.execute(f"SELECT ts / 600 * 600, count(*) FROM dns WHERE ts >= ? AND {noise_clause()} GROUP BY 1", (t0,)):
            i = idx(ts)
            if 0 <= i < n:
                dns[i] = c
        per = collections.defaultdict(lambda: [0] * n)
        for ts, mac, b in r.execute("SELECT ts / 600 * 600, mac, sum(down + up) FROM app_min WHERE ts >= ? GROUP BY 1, 2", (t0,)):
            i = idx(ts)
            if not 0 <= i < n or not b:
                continue
            nm = named(names, mac)["name"]
            per[nm][i] += b
            if b > 200_000:
                awake[i].add(nm)
        periods = vpn_periods(r, t0, now)
    busy = sorted(per.items(), key=lambda kv: -sum(kv[1]))[:9]
    return {"now": now, "t0": t0, "bucket": B,
            "series": [[t0 + i * B, down[i] / cnt[i] if cnt[i] else None, up[i] / cnt[i] if cnt[i] else None, dns[i],
                        len(awake[i])] for i in range(n)],
            "devices": [{"name": k, "slots": v, "total": sum(v)} for k, v in busy], "periods": periods}


def api_companies(q):
    """DNS lookups per device per company, and how many the DNS filter blocked."""
    now = int(time.time())
    sp = span(q)
    with reader() as r:
        names = dns_clients(r)
        rows = r.execute(f"SELECT client, domain, status, count(*) FROM dns WHERE ts >= ? AND {noise_clause()} "
                         "GROUP BY client, domain, status", (now - sp,)).fetchall()
    cmap = company_map()
    cell = collections.defaultdict(lambda: {"n": 0, "blocked": 0, "doms": collections.Counter()})
    other = collections.Counter()
    for client, dom, st, n in rows:
        dev = names.get(client) or client
        c = company_of(dom, cmap) or "Everyone else"
        e = cell[(dev, c)]
        e["n"] += n
        e["blocked"] += n if st == "blocked" else 0
        e["doms"][dom] += n
        if c == "Everyone else":
            other[dom] += n
    devs, comps, cblk = collections.Counter(), collections.Counter(), collections.Counter()
    for (dv, c), e in cell.items():
        devs[dv] += e["n"]
        comps[c] += e["n"]
        cblk[c] += e["blocked"]
    dl = [d for d, _ in devs.most_common(14)]
    cl = [c for c, _ in comps.most_common() if c != "Everyone else"][:18] + (["Everyone else"] if "Everyone else" in comps else [])
    return {"now": now, "span": sp, "devices": [[d, devs[d]] for d in dl], "companies": [[c, comps[c], cblk[c]] for c in cl],
            "cells": [[dl.index(dv), cl.index(c), e["n"], e["blocked"], e["doms"].most_common(4)]
                      for (dv, c), e in cell.items() if dv in dl and c in cl],
            "other_top": other.most_common(12), "total": sum(devs.values())}


def api_pulse(q):
    """Every minute of the last 24 hours, per ping target: median round trip and loss."""
    now = int(time.time())
    t0 = now - 86400
    with reader() as r:
        out = collections.defaultdict(list)
        for ts, t, med, lo, hi, loss in r.execute("SELECT ts, target, rtt_med, rtt_min, rtt_max, loss FROM latency_min "
                                                  "WHERE ts >= ? ORDER BY ts", (t0,)):
            out[t].append([ts, None if med is None else round(med, 2), None if hi is None else round(hi, 1), round(loss or 0)])
        periods = vpn_periods(r, t0, now)
    targets = config.latency_targets()
    return {"now": now, "t0": t0, "targets": [t["name"] for t in targets], "hosts": {t["name"]: t["host"] for t in targets},
            "series": out, "periods": periods, "fix_ts": (CFG.get("pulse") or {}).get("fix_ts")}


def api_names(q):
    """Every name looked up in the period with its count, blocked count and number of asking devices; plus the
    names asked for the first time ever in this period."""
    sp = span(q)
    now = int(time.time())
    t0 = now - sp
    noise = noise_clause()
    with reader() as r:
        who = dns_clients(r)
        doms = [list(x) for x in r.execute(
            "SELECT domain, count(*) n, sum(status = 'blocked') b, count(DISTINCT client) nc, max(ts) FROM dns "
            f"WHERE ts >= ? AND domain != '' AND {noise} GROUP BY domain ORDER BY n DESC LIMIT 4000", (t0,))]
        start = r.execute("SELECT min(ts) FROM dns").fetchone()[0]
        dn = noise.replace("domain", "d.domain").replace("client", "d.client")
        new = [{"domain": d, "t": t, "who": who.get(c, c), "client": c, "blocked": st == "blocked"} for d, t, c, st in r.execute(
            "SELECT d.domain, d.ts, d.client, d.status FROM dns d JOIN (SELECT domain, min(ts) t FROM dns GROUP BY domain "
            f"HAVING t >= ?) f ON d.domain = f.domain AND d.ts = f.t WHERE d.domain != '' AND {dn} "
            "GROUP BY d.domain ORDER BY d.ts", (t0,))]
    return {"now": now, "span": sp, "history_start": start, "domains": doms, "new": new[-3000:]}


def api_dnsspeed(q):
    """How long lookups take: forwarded lookups only, since cached and blocked answers come from the router itself."""
    sp = span(q)
    now = int(time.time())
    t0 = now - sp
    b = 3600 if sp <= 172800 else 21600
    noise = noise_clause()
    with reader() as r:
        who = dns_clients(r)
        fw = r.execute(f"SELECT ts, client, domain, reply_ms FROM dns WHERE ts >= ? AND status = 'forwarded' "
                       f"AND reply_ms IS NOT NULL AND {noise}", (t0,)).fetchall()
        mix = [list(x) for x in r.execute(
            f"SELECT ts / {b} * {b} t, sum(status = 'cached'), sum(status = 'forwarded'), sum(status = 'blocked') FROM dns "
            f"WHERE ts >= ? AND {noise} GROUP BY t ORDER BY t", (t0,))]
        per = collections.defaultdict(lambda: [0, 0, 0])
        for c, st, n in r.execute(f"SELECT client, status, count(*) FROM dns WHERE ts >= ? AND {noise} GROUP BY client, status", (t0,)):
            per[c][{"cached": 0, "forwarded": 1, "blocked": 2}.get(st, 1)] += n
        periods = vpn_periods(r, t0, now)
    edges = [0.5 * 2 ** (i / 2) for i in range(32)]
    hist = [0] * (len(edges) + 1)
    hours, doms, cl = collections.defaultdict(list), collections.defaultdict(list), collections.defaultdict(list)
    for ts, c, d, ms in fw:
        hist[bisect.bisect(edges, ms)] += 1
        hours[ts // b * b].append(ms)
        doms[d].append(ms)
        cl[c].append(ms)
    qf = lambda v, f: sorted(v)[int(f * (len(v) - 1))] if v else None
    allv = [x[3] for x in fw]
    slow = sorted(([d, len(v), qf(v, .5), max(v)] for d, v in doms.items() if len(v) >= 3), key=lambda x: -x[2])[:20]
    clients = sorted(([who.get(c, c), c, sum(n), n[0], n[1], n[2], qf(cl.get(c, []), .5)] for c, n in per.items()),
                     key=lambda x: -x[2])[:14]
    return {"now": now, "span": sp, "bucket": b, "edges": edges, "hist": hist, "periods": periods,
            "stats": {"n": len(allv), "med": qf(allv, .5), "p90": qf(allv, .9), "p99": qf(allv, .99),
                      "max": max(allv) if allv else None, "over1s": sum(1 for v in allv if v > 1000)},
            "hours": [[t, len(v), qf(v, .5), qf(v, .9)] for t, v in sorted(hours.items())], "mix": mix, "slow": slow,
            "clients": clients}


def api_bloat(q):
    sp = span(q)
    now = int(time.time())
    t0 = now - sp
    pub = config.public_target_names()
    ref = (CFG.get("bloat") or {}).get("ping_target") or (pub[0] if pub else None)
    shown = list(dict.fromkeys(pub + ([config.uplink_name()] if CFG["uplink"].get("ip") else [])))
    with reader() as r:
        cm = [list(x) for x in r.execute("SELECT ts, dev, tin, bytes, drops, marks, av_us, pk_us FROM cake_min WHERE ts >= ? "
                                         "ORDER BY ts", (t0,))]
        lat = [list(x) for x in r.execute(
            f"SELECT ts, target, rtt_med, rtt_max, loss FROM latency_min WHERE ts >= ? AND target IN "
            f"({','.join('?' * len(shown)) or 'NULL'}) ORDER BY ts", (t0, *shown))]
        vit = {x[0]: (x[1], x[2], x[3], x[4]) for x in r.execute("SELECT ts, down, up, down_max, up_max FROM vitals_min WHERE ts >= ?", (t0,))}
        tests = [json.loads(x[0]) for x in r.execute("SELECT result FROM bloat_test ORDER BY ts DESC LIMIT 12")]
    by = collections.defaultdict(dict)
    for ts, tg, med, mx, loss in lat:
        by[ts][tg] = (med, mx, loss)
    scatter = []
    for ts, v in sorted(by.items()):
        cf, vv = v.get(ref), vit.get(ts // 60 * 60)
        if cf and cf[0] is not None and vv:
            scatter.append([ts, round((vv[0] or 0) / 1e6, 2), round((vv[1] or 0) / 1e6, 2), cf[0], cf[1], cf[2]])
    live = [{"ts": s["ts"], "devs": {d: {"bw": x["bw"], "dt": x["dt"], "names": x["names"],
                                         "tins": [[t["bytes"], t["drops"], t["marks"], t["av_us"], t["pk_us"], t["flows"]]
                                                  for t in x["tins"]]}
                                     for d, x in s["devs"].items()}} for s in list(BLOAT["live"])]
    cur = {d: {"bw": p.get("bw"), "opts": p.get("opts"), "names": p.get("names"), "dropped": p.get("dropped"),
               "sent": p.get("sent")} for d, p in BLOAT["prev"].items()}
    return {"now": now, "span": sp, "fix_ts": (CFG.get("bloat") or {}).get("fix_ts"), "devs": cake_devs(), "current": cur,
            "minutes": cm, "latency": lat, "ref_target": ref, "scatter": scatter, "live": live, "tests": tests,
            "busy": BLOAT["busy"], "load_test": bool((CFG.get("actions") or {}).get("load_test"))}
