# SPDX-License-Identifier: AGPL-3.0-or-later
"""Geography: country, network owner (ASN) and city for public IPv4 addresses.

Touches: reads the DB-IP Lite files (CC BY 4.0) in CFG["geo"]["dir"] (default <repo>/geo):
dbip-country-lite-*.csv.gz, dbip-asn-lite-*.csv.gz and optionally city4.bin + city4.txt.
Makes no network calls.

geo_loop loads the ranges once, in the background; geo_lookup and geo_city answer from memory
and return empty values until the files are loaded or when they are absent.
"""
import array
import bisect
import csv
import glob
import gzip
import ipaddress
import os
import sys

from . import config
from .config import CFG
from .state import LOG

GEO = {"ready": False, "error": None}


def geo_dir():
    return CFG["geo"].get("dir") or os.path.join(config.ROOT, "geo")


def geo_loop(db):
    """Loads IPv4 country and ASN ranges once."""
    try:
        base = geo_dir()
        newest = lambda pat: (sorted(glob.glob(os.path.join(base, pat))) or [None])[-1]
        cf, af = newest("dbip-country-lite-*.csv.gz"), newest("dbip-asn-lite-*.csv.gz")
        if not cf:
            GEO["error"] = "no DB-IP files in " + base
            LOG.info("geo: %s", GEO["error"])
            return
        v4 = lambda a: int(ipaddress.IPv4Address(a))
        cs, ce, cc = array.array("I"), array.array("I"), []
        with gzip.open(cf, "rt") as f:
            for row in csv.reader(f):
                if ":" in row[0]:
                    continue
                cs.append(v4(row[0]))
                ce.append(v4(row[1]))
                cc.append(sys.intern(row[2]))
        as_, ae, an, ao = array.array("I"), array.array("I"), array.array("I"), []
        if af:
            with gzip.open(af, "rt") as f:
                for row in csv.reader(f):
                    if ":" in row[0]:
                        continue
                    as_.append(v4(row[0]))
                    ae.append(v4(row[1]))
                    an.append(int(row[2] or 0))
                    ao.append(sys.intern(row[3]))
        GEO.update(cs=cs, ce=ce, cc=cc, as_=as_, ae=ae, an=an, ao=ao, ready=True, source=os.path.basename(cf))
        LOG.info("geo: %d country ranges, %d ASN ranges from %s", len(cs), len(as_), os.path.basename(cf))
        cb, ct = os.path.join(base, "city4.bin"), os.path.join(base, "city4.txt")
        if os.path.exists(cb) and os.path.exists(ct):
            raw = array.array("I")
            with open(cb, "rb") as f:
                raw.frombytes(f.read())
            with open(ct, encoding="utf-8") as f:
                places = f.read().split("\n")
            GEO.update(city_s=raw[0::2], city_i=raw[1::2], places=places, city=True)
            LOG.info("geo: %d city ranges, %d places", len(raw) // 2, len(places))
    except Exception as e:
        GEO["error"] = str(e)
        LOG.warning("geo: %s", e)


def geo_lookup(ip):
    """-> (country code, ASN, owner) for a public IPv4 address, else (None, None, None)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None, None, None
    if a.version != 4 or not GEO.get("ready") or not a.is_global:
        return None, None, None
    n = int(a)
    i = bisect.bisect_right(GEO["cs"], n) - 1
    cc = GEO["cc"][i] if i >= 0 and n <= GEO["ce"][i] else None
    j = bisect.bisect_right(GEO["as_"], n) - 1
    asn, org = (GEO["an"][j], GEO["ao"][j]) if j >= 0 and n <= GEO["ae"][j] else (None, None)
    return cc, asn, org


def geo_city(ip):
    """City, region and coordinates for a public IPv4 address, or None."""
    if not GEO.get("city"):
        return None
    try:
        n = int(ipaddress.IPv4Address(ip))
    except ValueError:
        return None
    i = bisect.bisect_right(GEO["city_s"], n) - 1
    if i < 0 or GEO["city_i"][i] == 0xFFFFFFFF:
        return None
    cc, region, city, lat, lon = GEO["places"][GEO["city_i"][i]].split("|")
    return {"cc": cc, "city": city, "region": region, "lat": float(lat), "lon": float(lon)}
