# SPDX-License-Identifier: AGPL-3.0-or-later
"""DNS source: reads every lookup the site's resolver answered and stores it in the dns table.

Touches: the router through router.py (`dnslog`, read-only); the dns and ip_name tables; S.live_dns.

A source is a reader that yields rows {ts, client, domain, qtype, status}. One reader is built in,
"dnsmasq": the gate's `dnslog` subcommand prints one JSON object per line for each lookup in the
router's dnsmasq query log:
    {"ts": 1700000000, "client": "192.0.2.10", "domain": "example.com", "qtype": "A", "status": "forwarded"}
status is one of forwarded, cached, blocked, other. Optional keys are stored when present:
reply_ms, upstream, and answers (a list of addresses, used to name destinations in ip_name).
The reader keeps a high-water mark, so a gate that prints the whole log on each call and a gate
that follows the log both work without duplicate rows.
"""
import ipaddress
import json
import time

from . import config, router
from .config import CFG
from .state import LOG, STOP, S

STATUSES = ("forwarded", "cached", "blocked", "other")


def normalise(obj):
    """One JSON object from the source -> a dns row tuple and its answers, or None when malformed."""
    try:
        ts = int(obj["ts"])
        client = str(obj["client"])[:64]
        domain = str(obj["domain"]).rstrip(".").lower()[:253]
    except (KeyError, TypeError, ValueError):
        return None
    qtype = str(obj.get("qtype") or "OTHER")[:12]
    status = obj.get("status") if obj.get("status") in STATUSES else "other"
    ms = obj.get("reply_ms")
    ms = float(ms) if isinstance(ms, (int, float)) else None
    up = obj.get("upstream")
    up = str(up)[:64] if up else None
    answers = [a for a in (obj.get("answers") or []) if isinstance(a, str)][:16]
    return (ts, client, domain, qtype, status, None, ms, up), answers


class DnsmasqSource:
    """Runs `netmon-gate dnslog` over ssh and yields one parsed object per line."""
    name = "dnsmasq"

    def lines(self):
        p = router.gate_stream("dnslog")
        try:
            for raw in p.stdout:
                if STOP.is_set():
                    break
                line = raw.decode("utf-8", "replace").strip()
                if not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if "gate" in obj:
                    LOG.warning("dnslog: gate said %s", obj)
                    S.dns_source["status"] = f"refused by the router gate: {obj['gate']}"
                    break
                yield obj
        finally:
            try:
                p.kill()
                p.wait(timeout=5)
            except Exception:
                pass


SOURCES = {"dnsmasq": DnsmasqSource}


def source():
    return SOURCES.get(CFG["dns"].get("source") or "dnsmasq", DnsmasqSource)()


def _flush(db, rows, names):
    db.many("INSERT INTO dns(ts, client, domain, qtype, status, status_code, reply_ms, upstream) VALUES(?,?,?,?,?,?,?,?)",
            rows)
    if names:
        db.many("INSERT INTO ip_name VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET domain=excluded.domain, last=excluded.last",
                [(ip, d, t) for ip, (d, t) in names.items()])


def dns_loop(db):
    """Reads the source, keeps the latest lookups in memory and writes them in batches every 2 s."""
    src = source()
    S.dns_source.update(name=src.name, status="starting")
    hwm = int(db.meta("dns_hwm", 0) or 0)
    at_hwm = set()
    while not STOP.is_set():
        rows, names, last = [], {}, time.time()
        got = 0
        try:
            for obj in src.lines():
                n = normalise(obj)
                if not n:
                    continue
                row, answers = n
                key = row[:4]
                if row[0] < hwm or (row[0] == hwm and key in at_hwm):
                    continue
                if row[0] > hwm:
                    hwm, at_hwm = row[0], set()
                at_hwm.add(key)
                got += 1
                rows.append(row)
                S.live_dns.append({"ts": row[0], "client": row[1], "domain": row[2], "qtype": row[3], "status": row[4]})
                for a in answers:
                    try:
                        ipaddress.ip_address(a)
                        names[a] = (row[2], row[0])
                    except ValueError:
                        pass
                if time.time() - last > 2 or len(rows) > 5000:
                    _flush(db, rows, names)
                    db.set_meta("dns_hwm", hwm)
                    rows, names, last = [], {}, time.time()
                    S.dns_source.update(status="reading", ts=int(last))
        except Exception as e:
            LOG.warning("dns source %s: %s", src.name, e)
        if rows:
            _flush(db, rows, names)
            db.set_meta("dns_hwm", hwm)
            S.dns_source.update(status="reading", ts=int(time.time()))
        if not got and router.reachable() is False:
            S.dns_source["status"] = "router unreachable"
        STOP.wait(15 if got else 60)


def noise_clause():
    """SQL that leaves out the collector's own check lookups (the check domains asked by the collector
    or by the router on its behalf), so they do not count as household traffic."""
    doms = sorted({c.get("query", "example.com") for c in config.checks() if c.get("kind") == "dns"}) or ["example.com"]
    clients = sorted({*config.router_addrs(), "127.0.0.1", *collector_addrs()})
    q = lambda xs: ", ".join("'%s'" % x.replace("'", "") for x in xs)
    return f"NOT (domain IN ({q(doms)}) AND client IN ({q(clients)}))"


_COLLECTOR_IP = {"ips": None}


def collector_addrs():
    """The collector's own address on the site network: CFG["collector"]["ip"], else the address the
    operating system would use to reach the router (found without sending a packet)."""
    if CFG["collector"].get("ip"):
        return [CFG["collector"]["ip"]]
    if _COLLECTOR_IP["ips"] is None:
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((CFG["router"]["ip"], 53))
            _COLLECTOR_IP["ips"] = [s.getsockname()[0]]
            s.close()
        except OSError:
            _COLLECTOR_IP["ips"] = []
    return _COLLECTOR_IP["ips"]
