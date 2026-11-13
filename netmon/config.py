# SPDX-License-Identifier: AGPL-3.0-or-later
"""Configuration: loads config.json into CFG, fills defaults, validates, and derives site facts.

Touches: reads one JSON file. Writes nothing.

CFG is the single loaded configuration object. It is filled in place by load(), so every module
that imported it sees the loaded values. Modules read CFG at call time, never at import time.
Every optional key has a default in DEFAULTS; the helpers below give the derived values
(router addresses, local networks, latency targets, the default check list) that several
modules need.
"""
import copy
import ipaddress
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRAND = "Netmon"

DEFAULTS = {
    "site": {"name": "My network", "short": "NET", "cc": "", "tz": ""},
    "router": {"name": "router", "model": "", "ip": "192.168.1.1", "ssh": "", "key": "", "gate": "/usr/bin/netmon-gate",
               "wan_iface": "eth1", "lan_bridges": {"lan": "br-lan"}, "addrs": [], "wan_addrs": [],
               "vitals_every_s": 10, "conns_every_s": 30, "ssh_options": [],
               "limits": {"load1": 2.5, "temp_c": 80, "mem_avail_kb": 80000}},
    "uplink": {"name": "uplink", "kind": "", "ip": "", "cidr": ""},
    "isp": {"name": "ISP"},
    "collector": {"name": "netmon", "data_dir": "/var/lib/netmon", "port": 7780, "bind": "::",
                  "allow": ["127.0.0.1/32", "::1/128"], "hosts": [], "url": "", "ip": "", "wait_for": ""},
    "zones": [],
    "dns": {"source": "dnsmasq", "log": "/tmp/dnsmasq.log", "upstream_label": "", "filter_name": "", "server": "",
            "path_text": ""},
    "latency_targets": {},
    "vpn": {"enabled": False, "label": "VPN", "interface": "wg0", "profile": "", "provider_org": "",
            "api_domains": [], "inside_addrs": [],
            "ip_check_url": "https://www.cloudflare.com/cdn-cgi/trace",
            "hosters": ["Mullvad", "M247", "Datacamp", "CDN77", "NordVPN", "Clouvider", "Leaseweb", "Packethub",
                        "Tefincom", "Private Internet", "ExpressVPN", "Surfshark", "Windscribe", "IVPN", "Kape",
                        "Zenlayer", "HostRoyale", "xTom", "Performive", "GSL Networks", "31173 Services"]},
    "alerts": {"email_to": "", "cooldown_s": 1800,
               "smtp": {"host": "", "port": 587, "user": "", "from": "", "starttls": True,
                        "password_env": "NETMON_SMTP_PASSWORD"}},
    "actions": {"vpn_switch": False, "load_test": False, "captures": True},
    "heal": {"vpn_off_when_tunnel_down": False, "tunnel_down_after_s": 600, "min_gap_s": 10800},
    "health_machines": [],
    "health": {"script": ""},
    "retention_days": 365,
    "retention": {"detail_days": 30, "cap_gb": 50},
    "checks": None,
    "app_names": {},
    "infrastructure": {},
    "adapters": {},
    "companies": {},
    "threats": {"watch_countries": ["RU", "BY", "KP", "IR", "SY", "CN"], "allow": []},
    "dpi": {"every_s": 300, "ifaces": []},
    "geo": {"dir": ""},
    "selftest": {"queue_dir": "", "data_dir": ""},
    "bloat": {"ping_target": "", "fix_ts": None},
    "pulse": {"fix_ts": None},
    "isp_dot_servers": ["9.9.9.9", "149.112.112.112", "1.1.1.1", "1.0.0.1"],
}

CFG = copy.deepcopy(DEFAULTS)
PATH = {"file": None}


def _merge(base, over):
    """Deep merge: dicts merge key by key, every other value from `over` replaces the base."""
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def read(path):
    """Parses a config file and returns the merged dict, without installing it."""
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, dict):
        raise ValueError("the file must hold one JSON object")
    return _merge(DEFAULTS, raw), raw


def load(path):
    """Loads a config file into CFG in place."""
    merged, _ = read(path)
    CFG.clear()
    CFG.update(merged)
    PATH["file"] = os.path.abspath(path)
    return CFG


def _net(v):
    return ipaddress.ip_network(str(v), strict=False)


def validate(cfg, raw=None):
    """Returns a list of readable problems. An empty list means the config is usable."""
    errs = []

    def need(cond, msg):
        if not cond:
            errs.append(msg)

    raw = raw if raw is not None else cfg
    for key in ("site", "router", "collector"):
        need(isinstance(raw.get(key), dict), f'"{key}" is missing or is not an object')
    r = cfg.get("router", {})
    try:
        ipaddress.ip_address(r.get("ip", ""))
    except ValueError:
        errs.append(f'router.ip "{r.get("ip")}" is not an IP address')
    need(isinstance(r.get("gate"), str) and r["gate"].startswith("/"), "router.gate must be an absolute path on the router")
    need(isinstance(r.get("wan_iface"), str) and r["wan_iface"], "router.wan_iface must be an interface name")
    need(isinstance(r.get("lan_bridges"), dict), 'router.lan_bridges must map zone keys to bridges, e.g. {"lan": "br-lan"}')
    c = cfg.get("collector", {})
    need(isinstance(c.get("port"), int) and 0 < c["port"] < 65536, "collector.port must be a number from 1 to 65535")
    need(isinstance(c.get("data_dir"), str) and c["data_dir"], "collector.data_dir must be a folder path")
    if isinstance(c.get("allow"), list) and c["allow"]:
        for n in c["allow"]:
            try:
                _net(n)
            except ValueError:
                errs.append(f'collector.allow entry "{n}" is not an address or network')
    else:
        errs.append("collector.allow must list at least one address or network")
    zones = cfg.get("zones", [])
    if not isinstance(zones, list):
        errs.append("zones must be a list")
        zones = []
    for i, z in enumerate(zones):
        if not isinstance(z, dict) or not z.get("key") or not z.get("cidr"):
            errs.append(f"zones[{i}] needs at least key and cidr")
            continue
        try:
            _net(z["cidr"])
        except ValueError:
            errs.append(f'zones[{i}].cidr "{z["cidr"]}" is not a network')
    for ip_key in ("uplink",):
        ip = (cfg.get(ip_key) or {}).get("ip")
        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                errs.append(f'{ip_key}.ip "{ip}" is not an IP address')
    lt = cfg.get("latency_targets")
    need(isinstance(lt, (dict, list)), "latency_targets must be an object of name: address, or a list")
    need((cfg.get("dns") or {}).get("source") == "dnsmasq", 'dns.source must be "dnsmasq" (the only built-in reader)')
    a = cfg.get("alerts") or {}
    need(isinstance(a.get("email_to", ""), str), "alerts.email_to must be a string (empty means log only)")
    if a.get("email_to"):
        need(bool((a.get("smtp") or {}).get("host")), "alerts.smtp.host is required when alerts.email_to is set")
    need(isinstance(cfg.get("health_machines"), (list, dict)), "health_machines must be a list")
    rd = cfg.get("retention_days")
    need(isinstance(rd, int) and rd > 0, "retention_days must be a positive whole number")
    ch = cfg.get("checks")
    if ch is not None:
        if not isinstance(ch, list):
            errs.append("checks must be a list")
        else:
            for i, x in enumerate(ch):
                if not isinstance(x, dict) or not x.get("name") or not x.get("kind"):
                    errs.append(f"checks[{i}] needs name and kind")
    for k in ("actions", "heal"):
        for sk, sv in (cfg.get(k) or {}).items():
            if sk.endswith(("_s",)):
                continue
            need(isinstance(sv, bool), f"{k}.{sk} must be true or false")
    return errs


# ---------------------------------------------------------------- derived values


def data_dir():
    return CFG["collector"]["data_dir"]


def db_path():
    return os.path.join(data_dir(), "netmon.db")


def router_name():
    return CFG["router"].get("name") or "router"


def uplink_name():
    return CFG["uplink"].get("name") or "uplink"


def filter_name():
    d = CFG["dns"]
    return d.get("filter_name") or f"DNS filter on {router_name()}"


def dns_server():
    return CFG["dns"].get("server") or CFG["router"]["ip"]


def zones():
    return [z for z in CFG.get("zones", []) if isinstance(z, dict) and z.get("cidr")]


def lan_networks():
    nets = []
    for z in zones():
        try:
            nets.append(_net(z["cidr"]))
        except ValueError:
            pass
    if not nets:
        nets.append(_net(CFG["router"]["ip"] + "/24"))
    return nets


def fenced_networks():
    out = []
    for z in zones():
        if z.get("fenced"):
            try:
                out.append(_net(z["cidr"]))
            except ValueError:
                pass
    return out


def in_nets(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


def router_addrs():
    """Every address that belongs to the router: its own, its configured extras, and each zone's gateway."""
    r = CFG["router"]
    out = {r["ip"], *r.get("addrs", []), *r.get("wan_addrs", [])}
    for n in lan_networks():
        if n.num_addresses > 2:
            out.add(str(n.network_address + 1))
    return out


def zone_of_bridge(bridge):
    for key, br in CFG["router"].get("lan_bridges", {}).items():
        if br == bridge:
            return key
    return None


def bridges():
    return list(CFG["router"].get("lan_bridges", {}).values())


def latency_targets():
    """[{name, host}] from either the object form {name: host} or the list form."""
    lt = CFG.get("latency_targets") or {}
    if isinstance(lt, dict):
        out = [{"name": k, "host": v} for k, v in lt.items()]
    else:
        out = [{"name": t.get("name") or t.get("host"), "host": t.get("host")} for t in lt if isinstance(t, dict)]
    if not out:
        out = [{"name": router_name(), "host": CFG["router"]["ip"]}]
        if CFG["uplink"].get("ip"):
            out.append({"name": uplink_name(), "host": CFG["uplink"]["ip"]})
    return out


def local_target_names():
    """Latency targets inside the site (the router and the uplink): the control group for VPN comparisons."""
    local = set()
    for t in latency_targets():
        try:
            if ipaddress.ip_address(t["host"]).is_private:
                local.add(t["name"])
        except ValueError:
            pass
    return local


def public_target_names():
    return [t["name"] for t in latency_targets() if t["name"] not in local_target_names()]


def collector_url():
    c = CFG["collector"]
    return c.get("url") or f"http://{c.get('name') or 'localhost'}:{c['port']}/"


def health_machines():
    """{id: machine dict} from either the list form [{id, name, via, ...}] or the object form."""
    hm = CFG.get("health_machines") or []
    if isinstance(hm, dict):
        return hm
    return {m.get("id") or m.get("name"): m for m in hm if isinstance(m, dict) and (m.get("id") or m.get("name"))}


def site():
    """The `site` block of /api/now: names and addresses the web shows instead of built-in words."""
    s, r, u = CFG["site"], CFG["router"], CFG["uplink"]
    return {"name": s.get("name", ""), "short": s.get("short", ""), "cc": s.get("cc", ""),
            "router": {"name": router_name(), "model": r.get("model", ""), "ip": r.get("ip", "")},
            "uplink": {"name": uplink_name(), "kind": u.get("kind", ""), "ip": u.get("ip", "")},
            "isp": {"name": CFG["isp"].get("name", "")},
            "collector": CFG["collector"].get("name", ""),
            "filter": filter_name(),
            "zones": [{"key": z.get("key"), "name": z.get("name") or z.get("key"), "sub": z.get("cidr"),
                       "fenced": bool(z.get("fenced"))} for z in zones()]}


def default_checks():
    """The check list used when config.json has no "checks" key, built from the site's own names."""
    rn, un = router_name(), uplink_name()
    rip, uip = CFG["router"]["ip"], CFG["uplink"].get("ip")
    out = [
        {"name": "router-ping", "title": f"{rn} answers", "group": rn, "kind": "ping", "host": rip,
         "rtt_warn": 20, "rtt_crit": 200, "every": 30},
        {"name": "router-cpu", "title": f"{rn} CPU", "group": rn, "kind": "router", "metric": "cpu",
         "warn": 70, "crit": 90, "every": 30},
        {"name": "router-temp", "title": f"{rn} temperature", "group": rn, "kind": "router", "metric": "temp",
         "warn": 75, "crit": 85, "every": 60},
        {"name": "router-mem", "title": f"{rn} free memory", "group": rn, "kind": "router", "metric": "mem",
         "warn": 120, "crit": 70, "every": 60},
        {"name": "router-conntrack", "title": f"{rn} connection table", "group": rn, "kind": "router",
         "metric": "conntrack", "warn": 60, "crit": 85, "every": 60},
        {"name": "router-classifier", "title": f"{rn} traffic classifier", "group": rn, "kind": "router",
         "metric": "netifyd", "every": 60},
        {"name": "router-ports", "title": f"{rn} wired ports at full speed", "group": rn, "kind": "ports", "every": 60},
        {"name": "router-feed", "title": "Traffic data arriving", "group": rn, "kind": "feed", "warn": 60, "crit": 300,
         "every": 30},
        {"name": "router-dns", "title": f"{rn} DNS answers", "group": "DNS", "kind": "dns", "server": dns_server(),
         "query": "example.com", "every": 60},
    ]
    if uip:
        out.append({"name": "uplink-ping", "title": f"{un} answers", "group": "Internet", "kind": "ping", "host": uip,
                    "rtt_warn": 30, "rtt_crit": 300, "every": 60})
    for t in latency_targets():
        if t["name"] in public_target_names():
            out.append({"name": "internet-ping", "title": f"{t['name']} reachable", "group": "Internet", "kind": "ping",
                        "host": t["host"], "rtt_warn": 60, "rtt_crit": 400, "every": 60})
            break
    out += [
        {"name": "web", "title": "Websites load (example.com)", "group": "Internet", "kind": "http",
         "url": "https://example.com/", "every": 120},
        {"name": "collector-disk", "title": "Collector disk space", "group": "Collector", "kind": "disk",
         "path": data_dir(), "warn_free_pct": 15, "crit_free_pct": 5, "every": 600},
        {"name": "collector-dbsize", "title": "Traffic log size", "group": "Collector", "kind": "dbsize", "every": 600},
        {"name": "new-devices", "title": "New devices to review", "group": "Security", "kind": "newdevices",
         "every": 60, "attempts": 1},
    ]
    if CFG["vpn"].get("enabled"):
        out.append({"name": "vpn-expected", "title": "Devices that need a VPN are on it", "group": "Security",
                    "kind": "vpn", "every": 60})
    if health_machines():
        out.append({"name": "machine-health", "title": "Machines healthy", "group": "Machines", "kind": "machines",
                    "every": 300})
    out.append({"name": "self-test", "title": "Self-test runs and passes", "group": "Collector", "kind": "selftest",
                "every": 120, "attempts": 2, "stale_s": 2700})
    return out


def checks():
    ch = CFG.get("checks")
    return ch if isinstance(ch, list) else default_checks()


def retention():
    """(detail_days, minute_days, cap_gb)."""
    r = CFG.get("retention") or {}
    minute_days = r.get("minute_days") or CFG.get("retention_days") or 365
    detail_days = min(r.get("detail_days") or 30, minute_days)
    return detail_days, minute_days, r.get("cap_gb") or 50
