# SPDX-License-Identifier: AGPL-3.0-or-later
"""Collectors: the loops that read the router and the network and store what they see.

Touches: the router through router.py (feed, vitals, conns, links, leases, protos, cake: all
read-only); ICMP pings from the collector to CFG["latency_targets"]; the app_15s, app_min,
vitals_min, conn, link_min, latency_min and cake_min tables; live state in state.S.

Every loop backs off while the router reports itself busy (S.router_hot) and skips a round
quietly when the router is unreachable; router.py logs the change once.
"""
import collections
import contextlib
import ipaddress
import json
import re
import shutil
import statistics
import subprocess
import sys
import threading
import time
import concurrent.futures

from . import classify, config, router
from .config import CFG
from .state import LOG, STOP, S

# ---------------------------------------------------------------- traffic feed


def feed_loop(db):
    """The classifier's aggregated stream: one JSON object per 15 s batch."""
    backoff = 5
    dec = json.JSONDecoder()
    while not STOP.is_set():
        if S.router_hot:
            S.feed_status = "paused: router busy"
            STOP.wait(60)
            continue
        if router.reachable() is False:
            S.feed_status = "router unreachable"
        try:
            p = router.gate_stream("feed")
        except OSError as e:
            LOG.warning("feed: %s", e)
            STOP.wait(60)
            continue
        got = False
        buf = ""
        try:
            while not STOP.is_set():
                chunk = p.stdout.read1(65536)
                if not chunk:
                    break
                if not got:
                    got = True
                    S.feed_status = "connected"
                buf += chunk.decode("utf-8", "replace")
                while True:
                    buf = buf.lstrip()
                    if not buf:
                        break
                    if buf[0] != "{":
                        i = buf.find("{")
                        buf = buf[i:] if i >= 0 else ""
                        continue
                    try:
                        obj, idx = dec.raw_decode(buf)
                    except json.JSONDecodeError:
                        break
                    buf = buf[idx:]
                    if "gate" in obj:
                        S.feed_status = f"refused by the router gate: {obj['gate']}"
                        LOG.warning("feed: gate said %s", obj)
                        backoff = 300
                    else:
                        handle_batch(db, obj)
                        backoff = 5
                if len(buf) > 5_000_000:
                    buf = ""
        except Exception:
            LOG.exception("feed")
        finally:
            try:
                p.kill()
                p.wait(timeout=5)
            except Exception:
                pass
        if S.feed_status == "connected":
            S.feed_status = "reconnecting"
        elif not got and S.feed_status == "starting":
            S.feed_status = "no data from the router"
        STOP.wait(backoff)
        backoff = min(backoff * 2, 300)


def handle_batch(db, b):
    ts = int(b.get("log_time_end") or time.time())
    now = int(time.time())
    rows, mins = [], {}
    minute = ts // 60 * 60
    for s in b.get("stats", []):
        mac = (s.get("local_mac") or "").lower()
        app = s.get("application_id") or "0.netify.unclassified"
        down, up, pk = int(s.get("download", 0)), int(s.get("upload", 0)), int(s.get("packets", 0))
        rows.append((ts, mac, s.get("local_ip", ""), app, int(s.get("protocol_id", 0)), down, up, pk))
        d = mins.setdefault((minute, mac, app), [0, 0, 0])
        d[0] += down
        d[1] += up
        d[2] += pk
        classify.touch_device(db, mac, s.get("local_ip", ""), now)
    classify.note_new_apps(db, [(r[3], r[1], r[2]) for r in rows], now)
    db.many("INSERT INTO app_15s VALUES(?,?,?,?,?,?,?,?)", rows)
    db.many("INSERT INTO app_min(ts,mac,app,down,up,pkts) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(ts,mac,app) DO UPDATE SET down=down+excluded.down, up=up+excluded.up, pkts=pkts+excluded.pkts",
            [(k[0], k[1], k[2], v[0], v[1], v[2]) for k, v in mins.items()])
    S.feed_ts = now


# ---------------------------------------------------------------- router vitals


def vitals_loop(db):
    prev = None
    every = CFG["router"].get("vitals_every_s", 10)
    wan = CFG["router"]["wan_iface"]
    while not STOP.is_set():
        t0 = time.time()
        try:
            rc, out = router.gate("vitals")
            if rc == 0 and out.strip():
                v = json.loads(out)
                now = int(time.time())
                if prev:
                    dt = v["ts"] - prev["ts"] or every
                    c1, c0 = v["cpu"], prev["cpu"]
                    tot = sum(c1) - sum(c0)
                    cpu = 100.0 * (tot - (c1[3] - c0[3])) / tot if tot > 0 else 0.0
                    i1, i0 = v.get("ifaces", {}).get(wan, [0, 0]), prev.get("ifaces", {}).get(wan, [0, 0])
                    down = max(i1[0] - i0[0], 0) * 8 / dt
                    up = max(i1[1] - i0[1], 0) * 8 / dt
                    v["cpu_pct"], v["down_bps"], v["up_bps"] = cpu, down, up
                    with S.lock:
                        S.trace.append((now, down, up))
                        S.router_trace.append((now, cpu, v["temp_mc"] / 1000))
                        S.minute[now // 60 * 60].append(v)
                    flush_minutes(db, now)
                with S.lock:
                    S.vitals, S.vitals_ts = v, now
                lim = CFG["router"]["limits"]
                hot = (v["load"][0] > lim["load1"] or v["temp_mc"] / 1000 > lim["temp_c"]
                       or v["mem_avail_kb"] < lim["mem_avail_kb"])
                if hot != S.router_hot:
                    LOG.warning("router %s", "busy: backing off" if hot else "calm again")
                S.router_hot = hot
                prev = v
        except Exception as e:
            LOG.warning("vitals: %s", e)
        wait = (60 if S.router_hot or router.reachable() is False else every) - (time.time() - t0)
        STOP.wait(max(wait, 1))


def flush_minutes(db, now):
    cur = now // 60 * 60
    with S.lock:
        done = [m for m in S.minute if m < cur]
        batches = {m: S.minute.pop(m) for m in done}
    for m, vs in batches.items():
        vs = [x for x in vs if "cpu_pct" in x]
        if not vs:
            continue
        mean = lambda k: sum(x[k] for x in vs) / len(vs)
        db.run("INSERT OR REPLACE INTO vitals_min VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
               (m, mean("down_bps"), mean("up_bps"), max(x["down_bps"] for x in vs),
                max(x["up_bps"] for x in vs), mean("cpu_pct"), max(x["cpu_pct"] for x in vs),
                sum(x["temp_mc"] for x in vs) / len(vs) / 1000, vs[-1]["mem_avail_kb"],
                vs[-1]["conntrack"][0], vs[-1]["wifi_clients"], vs[-1]["load"][0]))


# ---------------------------------------------------------------- connection table

CT_RE = re.compile(r"(\w+)=(\S+)")
CONN_ACTIVE = {}      # (src, dst, dport, proto) -> last time its byte count moved
CONN_BYTES = {}
EGRESS = {}           # conn key -> [last_seen, src, dst, dport, proto, egress]


def egress_of(src, dst, reply_dst):
    """Where the router sent a connection, from the reply half of its conntrack entry.
    "local": never left the site. "direct": replies came to a WAN address (router.wan_addrs).
    "tunnel": replies came to a VPN inside address (vpn.inside_addrs), or to any other outside-facing
    address while a VPN is configured and the WAN addresses are known."""
    try:
        internet = ipaddress.ip_address(dst).is_global
    except ValueError:
        internet = False
    if not internet or not reply_dst or reply_dst == src:
        return "local"
    vpn = CFG["vpn"]
    if reply_dst in set(vpn.get("inside_addrs") or []):
        return "tunnel"
    wan = set(CFG["router"].get("wan_addrs") or [])
    if vpn.get("enabled") and wan and reply_dst not in wan:
        return "tunnel"
    return "direct"


def conns_loop(db):
    every = CFG["router"].get("conns_every_s", 30)
    while not STOP.is_set():
        if not S.router_hot:
            try:
                lan = config.lan_networks()
                skip_dst = config.router_addrs()
                rc, out = router.gate("conns")
                now = int(time.time())
                rows = []
                for line in out.splitlines() if rc == 0 else []:
                    f = line.split()
                    if len(f) < 6 or f[0] != "ipv4":
                        continue
                    proto = f[2]
                    state = f[5] if proto == "tcp" and "=" not in f[5] else ""
                    o, r = {}, {}
                    for k, v in CT_RE.findall(line):
                        (r if k in o and k in ("src", "dst", "sport", "dport", "packets", "bytes") else o).setdefault(k, v)
                    src, dst = o.get("src", ""), o.get("dst", "")
                    try:
                        s_ip, d_ip = ipaddress.ip_address(src), ipaddress.ip_address(dst)
                    except ValueError:
                        continue
                    if not any(s_ip in n for n in lan):
                        continue
                    if d_ip.is_multicast or dst in skip_dst or (d_ip.is_private and o.get("dport") == "53"):
                        continue
                    dport = int(o.get("dport", 0) or 0)
                    k = f"{proto}|{src}|{o.get('sport', '')}|{dst}|{o.get('dport', '')}"
                    redir = 1 if r.get("src") and r.get("src") != dst else 0
                    EGRESS[k] = [now, src, dst, dport, proto, egress_of(src, dst, r.get("dst"))]
                    tb = int(o.get("bytes", 0)) + int(r.get("bytes", 0))
                    if CONN_BYTES.get(k) != tb:
                        CONN_BYTES[k] = tb
                        CONN_ACTIVE[(src, dst, dport, proto)] = now
                    rows.append((k, now, now, proto, src, int(o.get("sport", 0) or 0), dst, dport,
                                 int(o.get("bytes", 0)), int(r.get("bytes", 0)), state, redir))
                for ak in [ak for ak, t in CONN_ACTIVE.items() if now - t > 900]:
                    del CONN_ACTIVE[ak]
                for ek in [ek for ek, e in EGRESS.items() if now - e[0] > 900]:
                    del EGRESS[ek]
                if len(CONN_BYTES) > 20000:
                    CONN_BYTES.clear()
                db.many("INSERT INTO conn(k, first, last, proto, src, sport, dst, dport, bytes_up, bytes_down, state, redir) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(k) DO UPDATE SET "
                        "last=excluded.last, bytes_up=excluded.bytes_up, "
                        "bytes_down=excluded.bytes_down, state=excluded.state, redir=excluded.redir", rows)
            except Exception as e:
                LOG.warning("conns: %s", e)
        STOP.wait(every)


# ---------------------------------------------------------------- links, leases


def _int(x):
    return int(x) if x.lstrip("-").isdigit() else None


def links_loop(db):
    """How each device is attached: wired port or Wi-Fi band, signal and rate, from the gate's `links`."""
    while not STOP.is_set():
        try:
            rc, out = router.gate("links")
            if rc == 0:
                wan = CFG["router"]["wan_iface"]
                main_br = CFG["router"].get("lan_bridges", {}).get("lan") or (config.bridges() or ["br-lan"])[0]
                adapters = CFG.get("adapters") or {}
                wifi, arp, ports, fdb = {}, {}, {}, {}
                for line in out.splitlines():
                    f = line.split("|")
                    if f[0] == "wifi" and len(f) >= 5:
                        sig = _int(f[3].strip())
                        try:
                            rate = round(float(f[4]))
                        except ValueError:
                            rate = None
                        b = f[2].strip()
                        band = "2.4 GHz" if b.startswith("2") else "5 GHz" if b.startswith("5") else \
                            "6 GHz" if b.startswith("6") else b or "Wi-Fi"
                        wifi[f[1].lower()] = {"band": band, "signal": sig, "rate_mbps": rate}
                    elif f[0] == "arp" and len(f) >= 4:
                        arp[f[1].lower()] = {"ip": f[2], "bridge": f[3]}
                    elif f[0] == "port" and len(f) >= 13:
                        spd, mx, pm = _int(f[4]), _int(f[5]), _int(f[6])
                        best = min(mx, pm) if mx and pm else mx
                        up = f[3] == "1" and (spd or 0) > 0
                        ports[f[1]] = {"name": f[1], "wan": f[1] == wan, "port_no": int(f[2], 16) if f[2] else None,
                                       "up": up, "speed": spd if up else None, "max": mx, "partner_max": pm, "best": best,
                                       "degraded": bool(up and best and spd < best),
                                       "rx_errors": _int(f[7]), "tx_errors": _int(f[8]), "rx_dropped": _int(f[9]),
                                       "tx_dropped": _int(f[10]), "rx_bytes": _int(f[11]), "tx_bytes": _int(f[12]), "macs": []}
                    elif f[0] == "fdb" and len(f) >= 4:
                        fdb[(f[1], f[2].lower())] = int(f[3])
                links = {}
                for mac, w in wifi.items():
                    links[mac] = {"kind": "wifi", "band": w["band"], "signal": w["signal"], "rate_mbps": w["rate_mbps"],
                                  "ip": arp.get(mac, {}).get("ip"),
                                  "snr": (w["signal"] + 58) if w["signal"] is not None else None}
                by_no = {p["port_no"]: p for p in ports.values() if p["port_no"]}
                for (br, mac), no in fdb.items():
                    if br == main_br and no in by_no:
                        by_no[no]["macs"].append(mac)
                for mac, a in arp.items():
                    if mac in links:
                        continue
                    adapter = next((lab for pfx, lab in adapters.items() if mac.startswith(pfx.lower())), None)
                    port = by_no.get(fdb.get((a["bridge"], mac))) if a["bridge"] == main_br else None
                    links[mac] = {"kind": "wired", "adapter": bool(adapter), "speed": adapter,
                                  "zone": config.zone_of_bridge(a["bridge"]) or "lan", "ip": a["ip"],
                                  "port": port["name"] if port else None,
                                  "port_speed": port["speed"] if port else None, "port_best": port["best"] if port else None,
                                  "port_degraded": port["degraded"] if port else False,
                                  "port_shared": len(port["macs"]) > 1 if port else False}
                S.links = links
                if ports:
                    S.ports = ports
                minute = int(time.time()) // 60 * 60
                db.many("INSERT OR REPLACE INTO link_min VALUES(?,?,?,?,?,?,?,?)",
                        [(minute, m, l["kind"], l.get("band"), l.get("signal"), l.get("rate_mbps"), l.get("port"),
                          l.get("port_speed")) for m, l in links.items()])
        except Exception as e:
            LOG.warning("links: %s", e)
        STOP.wait(30)


def leases_loop(db):
    """DHCP names from the router's lease file, and the classifier's protocol names once."""
    while not STOP.is_set():
        try:
            rc, out = router.gate("leases")
            now = int(time.time())
            for line in out.splitlines() if rc == 0 else []:
                f = line.split()
                if len(f) >= 4:
                    classify.touch_device(db, f[1].lower(), f[2], now, f[3] if f[3] != "*" else "")
            if rc == 0 and not S.protos:
                rc, out = router.gate("protos", timeout=30)
                for line in out.splitlines():
                    m = re.match(r"\s*(\d+):\s*(.+?)\s*$", line)
                    if m:
                        S.protos[int(m.group(1))] = m.group(2)
        except Exception as e:
            LOG.warning("leases: %s", e)
        STOP.wait(120)


# ---------------------------------------------------------------- latency

WAN_PING = threading.Lock()


def ping(host, count=5):
    """-> (median ms, loss %, min ms, max ms). One extra warm-up ping is sent and not counted, because the
    first reply of a new ping stream through some tunnels is dropped. Public targets are pinged one at a
    time at 4 a second, so per-site ICMP rate limits on a VPN do not show up as line loss."""
    try:
        internet = not ipaddress.ip_address(host).is_private
    except ValueError:
        internet = True
    darwin = sys.platform == "darwin"
    deadline = ["-t", "4"] if darwin else ["-w", "4"]
    try:
        with (WAN_PING if internet else contextlib.nullcontext()):
            p = subprocess.run([shutil.which("ping") or "ping", "-c", str(count + 1), "-i", "0.25" if internet else "0.2",
                                *deadline, "-n", host], capture_output=True, text=True, timeout=8)
    except (subprocess.TimeoutExpired, OSError):
        return None, 100.0, None, None
    first = "0" if darwin else "1"
    rtts = [float(t) for seq, t in re.findall(r"icmp_seq=(\d+) ttl=\d+ time=([\d.]+)", p.stdout) if seq != first]
    loss = 100.0 * max(count - len(rtts), 0) / count
    if not rtts:
        return None, loss, None, None
    return statistics.median(rtts), loss, min(rtts), max(rtts)


def latency_loop(db):
    targets = config.latency_targets()
    with concurrent.futures.ThreadPoolExecutor(max(len(targets), 1)) as ex:
        while not STOP.is_set():
            t0 = time.time()
            minute = int(t0) // 60 * 60
            res = dict(zip([t["name"] for t in targets], ex.map(lambda t: ping(t["host"]), targets)))
            rows = []
            for name, (med, loss, lo, hi) in res.items():
                S.latency[name] = {"med": med, "loss": loss, "min": lo, "max": hi, "ts": int(t0)}
                rows.append((minute, name, lo, med, hi, loss))
            db.many("INSERT OR REPLACE INTO latency_min VALUES(?,?,?,?,?,?)", rows)
            STOP.wait(max(60 - (time.time() - t0), 1))


# ---------------------------------------------------------------- CAKE shaper counters

CAKE_TINS = {4: ["Bulk", "Best effort", "Video", "Voice"], 1: ["Best effort"], 3: ["Bulk", "Best effort", "Voice"]}
BLOAT = {"prev": {}, "live": collections.deque(maxlen=360), "minute": collections.defaultdict(list), "busy": False,
         "last_test": None}


def cake_devs():
    """Shaper device -> plain label, from the WAN and VPN interface names."""
    wan, vif = CFG["router"]["wan_iface"], CFG["vpn"].get("interface") or "wg0"
    return {f"ifb4{vif}": "Download, inside the tunnel", vif: "Upload, inside the tunnel",
            f"ifb4{wan}": "Download, internet line", wan: "Upload, internet line"}


def _unit(v):
    m = re.match(r"^([\d.]+)([a-zA-Z]*)$", v)
    if not m:
        return None
    n, u = float(m.group(1)), m.group(2).lower()
    return n * {"us": 1, "ms": 1e3, "s": 1e6, "b": 1, "kb": 1024, "mb": 1048576, "bit": 1, "kbit": 1e3, "mbit": 1e6,
                "gbit": 1e9}.get(u, 1)


def parse_cake(text):
    """`tc -s qdisc` output in "## <dev>" sections -> {dev: {bw, opts, sent, pkts, dropped, names, tins}}."""
    out, dev = {}, None
    for line in text.splitlines():
        if line.startswith("## "):
            dev = line[3:].strip()
            continue
        if not dev:
            continue
        d = out.setdefault(dev, {"tins": {}, "names": []})
        m = re.search(r"bandwidth (\S+)", line)
        if line.startswith("qdisc cake") and m:
            d["bw"] = _unit(m.group(1))
            d["opts"] = line.split("bandwidth")[1].strip()[:160]
            continue
        m = re.match(r"\s*Sent (\d+) bytes (\d+) pkt \(dropped (\d+), overlimits (\d+)", line)
        if m:
            d["sent"], d["pkts"], d["dropped"] = int(m.group(1)), int(m.group(2)), int(m.group(3))
            continue
        cols = line.split()
        if cols and ((not d["names"] and cols[0] in ("Bulk", "Tin", "Best")) or cols[0] == "Bulk"):
            d["names"] = re.findall(r"Bulk|Best Effort|Video|Voice|Tin \d", line)
            continue
        if len(cols) >= 2 and cols[0] in ("pk_delay", "av_delay", "sp_delay", "backlog", "pkts", "bytes", "drops", "marks",
                                          "sp_flows", "bk_flows", "thresh"):
            for i, v in enumerate(_unit(x) for x in cols[1:]):
                d["tins"].setdefault(i, {})[cols[0]] = v
    for d in out.values():
        if not d["names"]:
            d["names"] = CAKE_TINS.get(len(d["tins"]), [f"Tier {i + 1}" for i in range(len(d["tins"]))])
    return out


def bloat_loop(db):
    """Every 10 s: the router's CAKE counters through the gate's `cake`; minute sums go to cake_min."""
    STOP.wait(10)
    while not STOP.is_set():
        try:
            rc, out = router.gate("cake", timeout=20)
            if rc != 0:
                STOP.wait(60)
                continue
            now = int(time.time())
            cur = parse_cake(out)
            smp = {"ts": now, "devs": {}}
            for dev, d in cur.items():
                p = BLOAT["prev"].get(dev)
                tins = []
                for i, t in sorted(d["tins"].items()):
                    pt = (p or {}).get("tins", {}).get(i, {})
                    dl = lambda k: ((t.get(k) or 0) - (pt.get(k) or 0) if (t.get(k) or 0) >= (pt.get(k) or 0)
                                    else (t.get(k) or 0)) if p else 0
                    tins.append({"bytes": dl("bytes"), "drops": dl("drops"), "marks": dl("marks"), "av_us": t.get("av_delay"),
                                 "pk_us": t.get("pk_delay"), "backlog": t.get("backlog"),
                                 "flows": (t.get("sp_flows") or 0) + (t.get("bk_flows") or 0)})
                dt = now - (p or {}).get("ts", now) or 10
                smp["devs"][dev] = {"bw": d.get("bw"), "dt": dt, "tins": tins, "names": d["names"]}
                BLOAT["prev"][dev] = {**d, "ts": now}
            if smp["devs"]:
                BLOAT["live"].append(smp)
            m = now // 60 * 60
            BLOAT["minute"][m].append(smp)
            for mm in [k for k in BLOAT["minute"] if k < m]:
                rows = collections.defaultdict(lambda: [0, 0, 0, [], 0])
                for sm in BLOAT["minute"].pop(mm):
                    for dev, dd in sm["devs"].items():
                        for i, t in enumerate(dd["tins"]):
                            r = rows[(dev, i)]
                            r[0] += t["bytes"]
                            r[1] += t["drops"]
                            r[2] += t["marks"]
                            if t["av_us"] is not None:
                                r[3].append(t["av_us"])
                            r[4] = max(r[4], t["pk_us"] or 0)
                db.many("INSERT OR REPLACE INTO cake_min VALUES(?,?,?,?,?,?,?,?)",
                        [(mm, dev, i, int(r[0]), int(r[1]), int(r[2]), (sum(r[3]) / len(r[3])) if r[3] else None, r[4])
                         for (dev, i), r in rows.items()])
        except Exception as e:
            LOG.warning("bloat: %s", e)
        STOP.wait(10)
