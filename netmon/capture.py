# SPDX-License-Identifier: AGPL-3.0-or-later
"""Packet captures: short traffic fingerprints on the LAN side and the view from the ISP side.

Touches: the router through router.py (`capture <iface> <secs>` and `ispview <secs>`, read-only,
rate-limited by the gate); dpi.py at the repository root for parsing; the meta table for
remembered tunnels and ISP-view summaries. Raw packets stay in memory for the analysis and are
never written anywhere.

dpi_loop takes a 12-second capture on each LAN bridge in turn every CFG["dpi"]["every_s"] seconds
while CFG["actions"]["captures"] is true. Tunnels found here feed the VPN status in vpn.py.
isp_run looks at handshakes leaving on the WAN interface and sorts each connection by what an
observer between the router and the ISP can read.
"""
import collections
import json
import re
import time

from . import classify, config, router
from . import state
from .config import CFG
from .db import reader
from .geo import geo_lookup
from .state import LOG, STOP, S, claim, short_time

try:
    import dpi as DPI
except ImportError:
    DPI = None

DPI_STATE = {"runs": collections.deque(maxlen=8), "tunnels": {}, "busy": False, "last": 0, "error": None}
ISP_STATE = {"run": None, "busy": False, "error": None, "by_vpn": {}}
PCAP_MAGIC = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1")
TTL_OS = [(1, 64, "Apple, Linux or Android (starts at 64)"), (65, 128, "Windows (starts at 128)"),
          (129, 255, "network equipment (starts at 255)")]


def hosters_re():
    names = [re.escape(x) for x in CFG["vpn"].get("hosters") or []]
    if CFG["vpn"].get("provider_org"):
        names.append(re.escape(CFG["vpn"]["provider_org"]))
    return re.compile("|".join(names), re.I) if names else re.compile(r"(?!x)x")


def provider_match(org):
    p = CFG["vpn"].get("provider_org")
    return bool(p and org and p.lower() in org.lower())


def plausible_tunnel(t):
    """A remembered tunnel is kept only if it was identified as one, or guessed on a VPN-like host."""
    return t.get("label") not in ("TLS", "TLS (session already running)", "QUIC", "QUIC (session already running)",
                                  "Unidentified") \
        or "VPN" in (t.get("provider") or "") or bool(hosters_re().search(t.get("org") or ""))


def ifaces():
    return CFG["dpi"].get("ifaces") or config.bridges() or ["br-lan"]


def dpi_enrich(flows):
    now = int(time.time())
    label = CFG["vpn"].get("label") or "VPN"
    api_doms = [d.lower() for d in CFG["vpn"].get("api_domains") or []]
    hosters = hosters_re()
    with reader() as r:
        who = classify.ip_directory(r)
        pn = classify.peer_names(r)
        vpnapi = set()
        for d in api_doms:
            vpnapi |= {x["client"] for x in r.execute("SELECT DISTINCT client FROM dns WHERE ts >= ? AND domain LIKE ?",
                                                      (now - 3600, "%" + d))}
    cmap = classify.company_map()
    for f in flows:
        d = who.get(f["lan"], {})
        f["device"] = d.get("name") or f["lan"]
        f["mac"] = d.get("mac", "")
        f["vendor"] = d.get("vendor", "")
        f["rname"] = f.get("sni") or pn.get(f["remote"]) or who.get(f["remote"], {}).get("name") or ""
        cc, asn, org = geo_lookup(f["remote"]) if not DPI.is_local(f["remote"]) else (None, None, None)
        f["cc"], f["org"] = cc, org
        if f["label"] == "TLS" and not f.get("sni") and f.get("ech") and provider_match(org) and f["rport"] == 443 \
                and f["proto"] == "tcp":
            f["label"], f["tunnel"], f["provider"] = f"{label} inside TLS", True, label
            f["evidence"].insert(0, "TLS ClientHello with no server name but an Encrypted Client Hello extension, "
                                    "to the VPN provider's network on 443: a VPN carried inside TLS")
        elif f["label"].startswith("TLS") and not f.get("sni") and not f["rname"] and provider_match(org) and f["rport"] == 443:
            f["label"], f["tunnel"], f["provider"], f["conf"] = f"{label} inside TLS (likely)", True, label, 0.7
            f["evidence"].insert(0, "TLS already running to the VPN provider's network with no service name behind it")
        known = DPI_STATE["tunnels"].get(f"{f['lan']}|{f['remote']}|{f['rport']}|{f['proto']}")
        if known and not f["tunnel"] and plausible_tunnel(known):
            f["tunnel"], f["provider"], f["tunnel_guess"] = True, known.get("provider"), known.get("guess", False)
            f["evidence"].append(f"same path identified earlier as {known.get('provider')} {known.get('label')} "
                                 f"({short_time(known.get('first'))})")
        f["service"] = classify.company_of(f["rname"], cmap)
        if f["tunnel"] and not f.get("provider"):
            f["provider"] = "Tailscale" if 41641 in (f["lport"], f["rport"]) else \
                label if (f["lan"] in vpnapi or provider_match(org)) else (org or "unknown provider")
    by_dev = collections.defaultdict(list)
    for f in flows:
        if not DPI.is_local(f["remote"]):
            by_dev[f["lan"]].append(f)
    for lan, fs in by_dev.items():
        tot = sum(f["pkts"] for f in fs)
        top = max(fs, key=lambda f: f["pkts"])
        vpn_like = lan in vpnapi or not top.get("org") or bool(hosters.search(top.get("org") or ""))
        if tot >= 60 and top["pkts"] >= 0.85 * tot and top["dur"] >= 6 and top["pkts_up"] >= 10 and top["pkts_dn"] >= 10 \
                and not top["tunnel"] and vpn_like and top["behaviour"] not in ("streaming or download", "upload"):
            top["tunnel"] = True
            top["tunnel_guess"] = True
            top["evidence"].append(f"carries {100 * top['pkts'] / tot:.0f}% of this device's outside packets on one "
                                   "steady two-way path")
            top["provider"] = (f"{label} (inside TLS?)" if lan in vpnapi else (top.get("org") or "unknown")) \
                if top["label"].startswith("TLS") else (top.get("org") or "unknown")
    return flows


def dpi_run(iface, secs=12, claimed=False):
    if DPI is None:
        return {"ok": False, "error": "dpi.py is not installed next to netmon.py"}
    if not claimed and not claim(DPI_STATE):
        return {"ok": False, "error": "a capture is already running"}
    try:
        rc, data = router.gate_bin(f"capture {iface} {int(secs)}", timeout=secs + 30)
        if not data.startswith(PCAP_MAGIC):
            msg = data[:120].decode("utf-8", "replace") or f"capture failed ({rc})"
            if "rate-limited" in msg:
                return {"ok": False, "error": "a capture ran less than a minute ago; try again shortly"}
            DPI_STATE["error"] = msg
            return {"ok": False, "error": msg}
        res = DPI.analyse(data)
        del data
        flows = dpi_enrich(res["flows"])
        now = int(time.time())
        for f in flows:
            f["inside"] = DPI.is_local(f["remote"])
            if f["inside"] and f["label"].startswith("HTTP"):
                f["label"] = "HTTP (inside the site)"
            if f["tunnel"] and not f["inside"]:
                k = f"{f['lan']}|{f['remote']}|{f['rport']}|{f['proto']}"
                t = DPI_STATE["tunnels"].get(k) or {"first": now}
                t.update(lan=f["lan"], remote=f["remote"], rport=f["rport"], proto=f["proto"], label=f["label"],
                         provider=f.get("provider"), guess=f.get("tunnel_guess", False), last=now, device=f["device"],
                         org=f.get("org"))
                DPI_STATE["tunnels"][k] = t
        for k in [k for k, t in DPI_STATE["tunnels"].items() if now - t["last"] > 6 * 3600]:
            del DPI_STATE["tunnels"][k]
        state.DBW.set_meta("dpi_tunnels", json.dumps(DPI_STATE["tunnels"]))
        run = {"ts": now, "iface": iface, "secs": secs, "flows": flows[:400], "n": len(flows),
               "pkts": sum(f["pkts"] for f in flows)}
        for f in run["flows"][120:]:
            f.pop("trace", None)
        DPI_STATE["runs"].appendleft(run)
        DPI_STATE["last"], DPI_STATE["error"] = now, None
        return {"ok": True, "flows": len(flows)}
    except Exception as e:
        DPI_STATE["error"] = str(e)
        LOG.warning("dpi: %s", e)
        return {"ok": False, "error": str(e)}
    finally:
        DPI_STATE["busy"] = False


def dpi_loop(db):
    if DPI is None:
        DPI_STATE["error"] = "dpi.py is not installed next to netmon.py"
        return
    try:
        DPI_STATE["tunnels"].update({k: t for k, t in json.loads(db.meta("dpi_tunnels", "{}")).items() if plausible_tunnel(t)})
    except (ValueError, TypeError):
        pass
    i = 0
    STOP.wait(40)
    while not STOP.is_set():
        if CFG["actions"].get("captures", True) and not S.router_hot and router.reachable() is not False:
            ifs = ifaces()
            dpi_run(ifs[i % len(ifs)], 12)
            i += 1
        STOP.wait(CFG["dpi"].get("every_s", 300))


def isp_analyse(data):
    items, quic, ttls, dns_plain = {}, collections.defaultdict(dict), collections.Counter(), []
    for ts, src, dst, proto, sp, dp, tot, pl, fl, plen, ttl in DPI.packets(data, with_ttl=True):
        if not DPI.is_local(src) or DPI.is_local(dst):
            continue
        key = (dst, dp, proto, sp)
        it = items.get(key)
        if it is None:
            it = items[key] = {"dst": dst, "dport": dp, "proto": proto, "sport": sp, "ts": ts, "kind": "open", "name": None,
                               "pkts": 0, "bytes": 0}
        it["pkts"] += 1
        it["bytes"] += tot
        if proto == "udp" and len(pl) >= 4 and pl[1:4] == b"\x00\x00\x00" and pl[0] in (1, 2, 3, 4):
            it["kind"] = "wireguard"
            continue
        if proto == "tcp" and fl & 0x02 and not fl & 0x10:
            lo = next((lab for a, b, lab in TTL_OS if a <= ttl <= b), None)
            if lo:
                ttls[lo] += 1
        if dp == 53:
            m = None
            try:
                q = pl[12:] if proto == "udp" else pl[14:]
                labels, i = [], 0
                while i < len(q) and q[i] and len(labels) < 12:
                    labels.append(q[i + 1:i + 1 + q[i]].decode("ascii", "replace"))
                    i += 1 + q[i]
                m = ".".join(labels)
            except (IndexError, ValueError):
                pass
            it.update(kind="dns-plain", name=m)
            dns_plain.append(m)
            continue
        if proto == "tcp" and pl[:1] == b"\x16":
            ch = DPI.tls_client_hello(pl)
            if ch:
                it.update(kind="tls", name=ch["sni"], ech=ch["ech"], pq=ch["pq"], alpn=ch["alpn"])
            continue
        if proto == "tcp" and dp == 80 and pl:
            m = re.match(rb"^(GET|POST|HEAD|PUT|OPTIONS) (\S+) HTTP/1\.[01]\r\n", pl)
            if m:
                host = re.search(rb"\r\nHost: ([^\r\n]{1,80})", pl, re.I)
                path = m.group(2).split(b"?")[0][:80].decode("ascii", "replace")
                it.update(kind="http", name=(host.group(1).decode("ascii", "replace") if host else dst), path=path,
                          method=m.group(1).decode(), query=b"?" in m.group(2))
            continue
        if proto == "udp" and pl and pl[0] & 0x80:
            r = DPI.quic_initial_pieces(pl)
            if r:
                quic[key + (r[0],)].update(r[1])
    for k, pieces in quic.items():
        ch, whole = DPI.assemble_client_hello(pieces)
        if ch:
            items[k[:4]].update(kind="quic", name=ch["sni"], ech=ch["ech"], pq=ch["pq"], complete=whole)
    return list(items.values()), ttls, dns_plain


def shortorg(o):
    return re.sub(r",?\s+(Inc\.?|LLC|Ltd\.?|Limited|GmbH|B\.V\.|AG|PBC|S\.A\.|Corporation|Corp\.?)$", "", o or "")


def isp_run(secs=20, claimed=False):
    from .vpn import vpn_switch_status
    if DPI is None:
        return {"ok": False, "error": "dpi.py is not installed next to netmon.py"}
    if not claimed and not claim(ISP_STATE):
        return {"ok": False, "error": "a look is already running"}
    try:
        rc, data = router.gate_bin(f"ispview {int(secs)}", timeout=secs + 30)
        if not data.startswith(PCAP_MAGIC[:2]):
            msg = data[:120].decode("utf-8", "replace") or f"capture failed ({rc})"
            ISP_STATE["error"] = "a capture ran less than a minute ago; try again shortly" if "rate-limited" in msg else msg
            return {"ok": False, "error": ISP_STATE["error"]}
        items, ttls, dns_plain = isp_analyse(data)
        del data
        now = int(time.time())
        with reader() as r:
            who = classify.ip_directory(r)
            pn = classify.peer_names(r)
            rows = r.execute("SELECT src, dst, dport, sport, proto FROM conn WHERE last >= ?", (now - 900,)).fetchall()
        owner = {(x["dst"], x["dport"], x["sport"], x["proto"]): x["src"] for x in rows}
        tunnels = {(t["remote"], t["rport"]): t for t in DPI_STATE["tunnels"].values()}
        dot = {x.strip() for x in CFG.get("isp_dot_servers") or []}
        rn, label = config.router_name(), CFG["vpn"].get("label") or "VPN"
        out = []
        for it in items:
            src = owner.get((it["dst"], it["dport"], it["sport"], it["proto"]))
            d = who.get(src, {}) if src else {}
            it["device"] = d.get("name") or (f"{rn} (the router itself)" if not src else src)
            it["mac"], it["vendor"] = d.get("mac", ""), d.get("vendor", "")
            it["inside_name"] = pn.get(it["dst"]) or ""
            cc, asn, org = geo_lookup(it["dst"])
            it["cc"], it["org"] = cc, org
            t = tunnels.get((it["dst"], it["dport"]))
            if it["kind"] == "wireguard":
                it["seen"] = "vpn"
                it["why"] = (f"a WireGuard VPN tunnel{f' (from {rn})' if not src else ''}: they see this server, "
                             f"{it['pkts']} packets and {it['bytes'] // 1000} kB in {secs} s, nothing inside")
                it["name"] = f"{label} server" if provider_match(org) else "VPN server"
            elif t:
                it["seen"], it["why"] = "vpn", f"a {t.get('provider') or 'VPN'} tunnel: they see the server and the amount of data, nothing inside"
            elif it["dport"] == 853 or (it["dst"] in dot and it["dport"] in (443, 853)):
                it["seen"], it["why"] = "dns-encrypted", f"encrypted DNS to {it.get('name') or it['dst']}: they see that you use it, not what you look up"
            elif it["kind"] == "dns-plain":
                it["seen"], it["why"] = "leak", "plain DNS leaving the site: the name looked up is readable"
            elif it["kind"] == "http":
                it["seen"], it["why"] = "full", "unencrypted HTTP: the whole address and everything sent are readable"
            elif it["kind"] in ("tls", "quic") and it.get("name"):
                it["seen"] = "name"
                it["why"] = "the site name travels in the open in the " + \
                            ("TLS" if it["kind"] == "tls" else "QUIC (decrypted with public keys)") + " handshake" + \
                            (" even though an ECH decoy was offered" if it.get("ech") else "")
            elif it["kind"] in ("tls", "quic"):
                it["seen"], it["why"] = "hidden", "Encrypted Client Hello: only the address and the company that owns it"
            else:
                it["seen"], it["why"] = "address", "only the address and the company that owns it (no handshake in the window)"
            out.append(it)
        order = {"leak": 0, "full": 1, "name": 2, "address": 3, "hidden": 4, "dns-encrypted": 5, "vpn": 6}
        out.sort(key=lambda i: (order[i["seen"]], i["device"], i.get("name") or i["dst"]))
        vs = vpn_switch_status() if CFG["vpn"].get("enabled") else {}
        ISP_STATE["run"] = {"ts": now, "secs": secs, "items": out[:600], "n": len(out), "ttl": dict(ttls),
                            "dns_plain": [x for x in dns_plain if x][:30],
                            "counts": dict(collections.Counter(i["seen"] for i in out)), "vpn": bool(vs.get("up")),
                            "names": sorted({i["name"] for i in out if i["seen"] in ("name", "full") and i.get("name")}),
                            "orgs": sorted({shortorg(i["org"]) for i in out if i.get("org")})}
        ISP_STATE["by_vpn"]["on" if vs.get("up") else "off"] = {k: v for k, v in ISP_STATE["run"].items() if k != "items"}
        state.DBW.set_meta("isp_by_vpn", json.dumps(ISP_STATE["by_vpn"]))
        ISP_STATE["error"] = None
        return {"ok": True, "items": len(out)}
    except Exception as e:
        ISP_STATE["error"] = str(e)
        LOG.warning("isp: %s", e)
        return {"ok": False, "error": str(e)}
    finally:
        ISP_STATE["busy"] = False
