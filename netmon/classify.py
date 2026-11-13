# SPDX-License-Identifier: AGPL-3.0-or-later
"""Names for things: device vendors, application names, destination names and the device table.

Touches: the device, app_seen, rdns and event tables; reads oui.txt and the classifier signature
cache in the data folder; asks the router for its signature list (`apps`) through router.py;
runs reverse DNS lookups (dig -x) against the router or the configured DNS server.

Classifier holds the router classifier's own signature list (host-name rules and address
ranges) and labels connections the per-device feed cannot. touch_device records a device and
raises a new-device event. device_names, ip_directory and peer_names give the API one consistent
name for every MAC and address.
"""
import collections
import concurrent.futures
import ipaddress
import os
import re
import shutil
import subprocess
import threading
import time

from . import alerts, config, router
from .config import CFG
from .db import reader
from .state import LOG, STOP, S, fmt_time

OUI = {}


def load_oui():
    p = os.path.join(config.ROOT, "oui.txt")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8", errors="replace"):
            if len(line) > 7 and not line.startswith("#"):
                OUI[line[:6].upper()] = line[7:].strip()


def vendor_of(mac):
    if not mac or len(mac) < 8:
        return ""
    try:
        if int(mac[1], 16) & 2:
            return "Private address"
    except ValueError:
        return ""
    return OUI.get(mac.replace(":", "")[:6].upper(), "")


def app_name(app_id):
    """'12023.netify.mozilla' -> 'Mozilla'. CFG["app_names"] overrides any name."""
    tail = app_id.split(".", 2)[-1] if app_id.count(".") >= 2 else app_id
    if tail == "unclassified":
        return "Unclassified"
    special = CFG.get("app_names", {})
    if tail in special:
        return special[tail]
    return " ".join(w.upper() if len(w) <= 3 and w not in ("app", "the") else w.capitalize() for w in tail.split("-"))


# ---------------------------------------------------------------- classifier signatures


class Classifier:
    """The router classifier's signature list: host-name rules and IPv4 address ranges."""

    def __init__(self):
        self.lock = threading.Lock()
        self.apps, self.doms, self.nets = {}, {}, {}

    def load(self, text):
        apps, doms, nets = {}, {}, collections.defaultdict(dict)
        for line in text.splitlines():
            parts = line.split(":", 2)
            if len(parts) != 3:
                continue
            kind, i, val = parts
            if kind == "app":
                apps[i] = val
            elif kind == "dom":
                doms[val.lower().lstrip("*.").rstrip(".")] = i
            elif kind == "net":
                try:
                    n = ipaddress.ip_network(val.strip(), strict=False)
                except ValueError:
                    continue
                if n.version == 4:
                    nets[n.prefixlen][int(n.network_address) >> (32 - n.prefixlen)] = i
        with self.lock:
            self.apps, self.doms = apps, doms
            self.nets = dict(sorted(nets.items(), reverse=True))
        return len(apps), len(doms), sum(len(v) for v in nets.values())

    def by_name(self, name):
        labels = (name or "").lower().rstrip(".").split(".")
        for k in range(len(labels) - 1):
            i = self.doms.get(".".join(labels[k:]))
            if i:
                return i
        return None

    def by_ip(self, ip):
        try:
            x = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None
        for plen, table in self.nets.items():
            i = table.get(x >> (32 - plen))
            if i:
                return i
        return None

    def classify(self, ip, name):
        """-> (application name, how it was recognised) or (None, None)."""
        i, via = (self.by_name(name), "host name") if name else (None, None)
        if not i:
            i, via = self.by_ip(ip), "address range"
        if not i:
            return None, None
        return app_name(f"{i}.{self.apps.get(i, 'netify.unknown')}"), via


CLS = Classifier()


def apps_list_loop(db):
    """Loads the signature list from the cache at start, then from the router once a day."""
    cache = os.path.join(config.data_dir(), "classifier-apps.conf")
    if os.path.exists(cache):
        LOG.info("signatures from cache: %s apps, %s host rules, %s ranges", *CLS.load(open(cache).read()))
    while not STOP.is_set():
        if not S.router_hot:
            try:
                rc, out = router.gate("apps", timeout=90)
                if rc == 0 and out.count("\n") > 1000:
                    with open(cache + ".new", "w") as f:
                        f.write(out)
                    os.replace(cache + ".new", cache)
                    LOG.info("signatures from router: %s apps, %s host rules, %s ranges", *CLS.load(out))
                    STOP.wait(86400)
                    continue
            except Exception as e:
                LOG.warning("signatures: %s", e)
        STOP.wait(1800)


# ---------------------------------------------------------------- devices

DEV_LOCK = threading.Lock()
DEV_SEEN = {}          # mac -> last write time, to throttle device upserts
APPS_SEEN = set()


def infra_name(mac):
    """Named infrastructure from CFG["infrastructure"]: an exact MAC, or a MAC prefix."""
    inf = CFG.get("infrastructure", {})
    if mac in inf:
        return inf[mac]
    for k, v in inf.items():
        if len(k) < 17 and mac.startswith(k):
            return v
    return None


def touch_device(db, mac, ip, now, hostname=None):
    """Records a sighting of a device; the first sighting outside the start-up baseline raises an event."""
    if not mac or infra_name(mac):
        return
    with DEV_LOCK:
        if hostname is None and now - DEV_SEEN.get(mac, 0) < 60:
            return
        DEV_SEEN[mac] = now
    row = db.one("SELECT known FROM device WHERE mac=?", (mac,))
    if row is None:
        baseline = float(db.meta("baseline_until", 0)) > now
        db.run("INSERT INTO device(mac, ip, hostname, vendor, first_seen, last_seen, known) VALUES(?,?,?,?,?,?,?)",
               (mac, ip, hostname or "", vendor_of(mac), now, now, 1 if baseline else 0))
        if not baseline:
            name = hostname or vendor_of(mac) or "unknown device"
            text = (f"A new device joined the network: {name}, address {ip}, "
                    f"card address {mac}. First seen {fmt_time(now)}.")
            db.event(now, "device", mac, 1, text)
            LOG.warning(text)
            alerts.notify(f"newdevice-{mac}", f"{config.BRAND}: new device on the network ({name})", text, 86400)
    elif hostname:
        db.run("UPDATE device SET ip=?, hostname=?, last_seen=? WHERE mac=?", (ip, hostname, now, mac))
    else:
        db.run("UPDATE device SET ip=?, last_seen=? WHERE mac=?", (ip, now, mac))


def note_new_apps(db, batch_apps, now):
    """The first sighting of an application anywhere on the network becomes an event."""
    fresh = [(a, m, ip) for a, m, ip in batch_apps if a not in APPS_SEEN]
    if not fresh:
        return
    baseline = float(db.meta("apps_baseline_until", 0)) > now
    for app, mac, ip in fresh:
        if app in APPS_SEEN:
            continue
        APPS_SEEN.add(app)
        db.run("INSERT OR IGNORE INTO app_seen VALUES(?,?,?)", (app, now, mac))
        if baseline or app.startswith("0."):
            continue
        d = db.one("SELECT label, hostname, vendor FROM device WHERE mac=?", (mac,))
        who = (d and (d[0] or d[1] or d[2])) or infra_name(mac) or mac
        text = f"New application on the network: {app_name(app)}, first used by {who} ({ip})."
        db.event(now, "app", app, None, text)
        LOG.info(text)


def device_names(r):
    out = {}
    for d in r.execute("SELECT * FROM device"):
        name = d["label"] or d["hostname"] or d["vendor"] or "Unknown device"
        out[d["mac"]] = {"name": name, "ip": d["ip"], "vendor": d["vendor"], "known": d["known"]}
    for mac in list(out):
        if infra_name(mac):
            out[mac] = dict(out[mac], name=infra_name(mac), known=1)
    return out


def named(names, mac):
    return names.get(mac) or ({"name": infra_name(mac), "ip": "", "vendor": "", "known": 1}
                              if infra_name(mac) else {"name": mac, "ip": "", "vendor": "", "known": 1})


def infra_addresses():
    """Address -> name for the router, each zone's gateway, the uplink and a separate DNS server."""
    rn = config.router_name()
    out = {CFG["router"]["ip"]: rn}
    for z in config.zones():
        try:
            n = ipaddress.ip_network(z["cidr"], strict=False)
        except ValueError:
            continue
        gw = str(n.network_address + 1)
        out.setdefault(gw, f"{rn} ({z.get('name') or z.get('key')} side)")
    if CFG["uplink"].get("ip"):
        out.setdefault(CFG["uplink"]["ip"], config.uplink_name())
    if config.dns_server() not in out:
        out[config.dns_server()] = config.filter_name()
    return out


def ip_directory(r):
    """Device IP -> {mac, name, vendor}, including live link addresses and the infrastructure."""
    names = device_names(r)
    out = {}
    for m, v in names.items():
        if v["ip"]:
            out[v["ip"]] = {"mac": m, "name": v["name"], "vendor": v["vendor"]}
    for m, l in list(S.links.items()):
        if l.get("ip") and l["ip"] not in out and m in names:
            out[l["ip"]] = {"mac": m, "name": names[m]["name"], "vendor": names[m]["vendor"]}
    for ip, name in infra_addresses().items():
        out.setdefault(ip, {"mac": "", "name": name, "vendor": "infra"})
    return out


def dns_clients(r):
    """DNS client address -> device name. Lookups the router makes itself carry its own address."""
    names = device_names(r)
    by_ip = {v["ip"]: v["name"] for v in names.values() if v["ip"]}
    for m, l in list(S.links.items()):
        if l.get("ip") and l["ip"] not in by_ip and m in names:
            by_ip[l["ip"]] = names[m]["name"]
    by_ip.update(router_self_names())
    return by_ip


def router_self_names():
    rn = config.router_name()
    out = {"127.0.0.1": f"{rn} itself", "::1": f"{rn} itself"}
    for ip in config.router_addrs():
        out[ip] = f"{rn} (for itself and fenced zones)"
    return out


def peer_names(r):
    rd = {x["ip"]: x["name"] for x in r.execute("SELECT ip, name FROM rdns WHERE name != ''")}
    rd.update({x["ip"]: x["domain"] for x in r.execute("SELECT ip, domain FROM ip_name")})
    return rd


# ---------------------------------------------------------------- reverse DNS

TAILNET = ipaddress.ip_network("100.64.0.0/10")
PTR_NAME = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*\.?$", re.I)
PTR_SKIP = ("in-addr.arpa", "ip6.arpa")


def dig():
    return shutil.which("dig") or "dig"


def ptr(ip):
    """Reverse DNS: tailnet addresses ask the tailnet resolver, every other address asks the site's DNS server."""
    a = ipaddress.ip_address(ip)
    server = "100.100.100.100" if a in TAILNET else config.dns_server()
    try:
        p = subprocess.run([dig(), "+short", "+time=2", "+tries=1", "-x", ip, f"@{server}"],
                           capture_output=True, text=True, timeout=6)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return parse_ptr(p.stdout)


def parse_ptr(out):
    """The first real host name in dig +short output: whole lines only, never error text or wildcards."""
    for line in out.splitlines():
        x = line.strip()
        if not PTR_NAME.match(x):
            continue
        x = x.rstrip(".")
        if not x.endswith(PTR_SKIP):
            return x
    return ""


def rdns_loop(db):
    """Names every destination the DNS log did not name, and every device that gave no name.
    At most 40 lookups per 20 s. Names are kept 7 days; failures are retried after 1 day."""
    with concurrent.futures.ThreadPoolExecutor(4) as ex:
        while not STOP.is_set():
            now = int(time.time())
            try:
                with reader() as r:
                    ips = [x[0] for x in r.execute(
                        "SELECT DISTINCT c.dst FROM conn c LEFT JOIN ip_name n ON n.ip=c.dst "
                        "LEFT JOIN rdns d ON d.ip=c.dst WHERE c.last >= ? AND n.ip IS NULL AND "
                        "(d.ip IS NULL OR (d.name='' AND d.ts < ?) OR d.ts < ?) LIMIT 40",
                        (now - 900, now - 86400, now - 7 * 86400))]
                    nameless = [(x[0], x[1]) for x in r.execute(
                        "SELECT mac, ip FROM device WHERE (hostname IS NULL OR hostname='') AND ip != '' "
                        "AND last_seen >= ? LIMIT 20", (now - 3600,))]
                todo = ips + [ip for _, ip in nameless if ip not in ips]
                res = dict(zip(todo, ex.map(ptr, todo))) if todo else {}
                db.many("INSERT INTO rdns VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET name=excluded.name, "
                        "ts=excluded.ts", [(ip, n, now) for ip, n in res.items()])
                for mac, ip in nameless:
                    n = res.get(ip, "")
                    if n:
                        n = re.sub(r"\.(lan|local|home|internal|tail[0-9a-f]+\.ts\.net)$", "", n)
                        db.run("UPDATE device SET hostname=? WHERE mac=? AND (hostname IS NULL OR hostname='')", (n, mac))
            except Exception as e:
                LOG.warning("rdns: %s", e)
            STOP.wait(20)


# ---------------------------------------------------------------- companies behind domain names

COMPANIES = [
    ("Apple", "apple.com icloud.com icloud-content.com mzstatic.com apple-dns.net aaplimg.com cdn-apple.com apple.news "
              "me.com apple-cloudkit.com applimg.com"),
    ("Google", "google.com googleapis.com gstatic.com googleusercontent.com gvt1.com gvt2.com youtube.com ytimg.com "
               "googlevideo.com doubleclick.net google-analytics.com googletagmanager.com googlesyndication.com "
               "app-measurement.com android.com googleadservices.com 1e100.net crashlytics.com firebaseio.com ggpht.com "
               "youtube-nocookie.com withgoogle.com"),
    ("Amazon", "amazon.com amazonaws.com media-amazon.com ssl-images-amazon.com amazonvideo.com primevideo.com aiv-cdn.net "
               "amazon-adsystem.com a2z.com alexa.com amazonalexa.com cloudfront.net amazontrust.com aiv-delivery.net"),
    ("Meta", "facebook.com facebook.net fbcdn.net instagram.com cdninstagram.com whatsapp.net whatsapp.com meta.com "
             "messenger.com fbsbx.com"),
    ("Microsoft", "microsoft.com msftconnecttest.com windows.com live.com office.com office.net microsoftonline.com bing.com "
                  "msn.com skype.com azure.com azureedge.net windowsupdate.com xbox.com linkedin.com licdn.com github.com "
                  "githubusercontent.com msedge.net sharepoint.com outlook.com trafficmanager.net azurefd.net microsoftapp.net"),
    ("Samsung", "samsung.com samsungcloud.com samsungapps.com samsungosp.com tizen.org samsungqbe.com "
                "samsungelectronics.com samsungdm.com"),
    ("Cloudflare", "cloudflare.com cloudflare-dns.com cloudflareinsights.com one.one.one.one cloudflarestream.com"),
    ("Akamai", "akamai.net akamaiedge.net akamaized.net akamaihd.net edgekey.net edgesuite.net akadns.net"),
    ("Anthropic", "anthropic.com claude.ai claude.com"),
    ("OpenAI", "openai.com chatgpt.com oaiusercontent.com"),
    ("Tailscale", "tailscale.com tailscale.io ts.net"),
    ("Netflix", "netflix.com nflxvideo.net nflxso.net nflximg.net nflxext.com"),
    ("Spotify", "spotify.com scdn.co spotifycdn.com"),
    ("ByteDance", "tiktok.com tiktokcdn.com byteoversea.com ibytedtos.com tiktokv.com bytedance.com"),
    ("TP-Link", "tplinkcloud.com tp-link.com tplinknbu.com tplinkra.com tapo.com"),
    ("Mozilla", "mozilla.org mozilla.com mozilla.net firefox.com"),
    ("Wikimedia", "wikipedia.org wikimedia.org wikidata.org"),
    ("Ad and tracking firms", "criteo.com scorecardresearch.com adnxs.com taboola.com outbrain.com hotjar.com segment.io "
                              "mixpanel.com amplitude.com datadoghq.com sentry.io branch.io appsflyer.com adjust.com "
                              "onesignal.com rubiconproject.com pubmatic.com casalemedia.com adsrvr.org quantserve.com "
                              "bluekai.com demdex.net omtrdc.net newrelic.com nr-data.net bugsnag.com applovin.com moloco.com "
                              "unityads.unity3d.com ironsrc.mobi vungle.com chartboost.com inmobi.com liftoff.io fyber.com "
                              "mintegral.com mtgglobals.com bidmachine.io"),
    ("Mullvad", "mullvad.net"), ("Reddit", "reddit.com redditspace.com redditmedia.com redd.it redditstatic.com"),
    ("Fastly", "fastly.net fastly.com fastlylb.net"),
]


def company_map():
    """Suffix -> company, from COMPANIES plus CFG["companies"] ({company: "suffix suffix ..."})."""
    pairs = list(COMPANIES) + list((CFG.get("companies") or {}).items())
    return {s: c for c, sfx in pairs for s in sfx.split()}


def company_of(domain, cmap=None):
    cmap = cmap or company_map()
    labels = (domain or "").lower().rstrip(".").split(".")
    for i in range(len(labels) - 1):
        c = cmap.get(".".join(labels[i:]))
        if c:
            return c
    return None
