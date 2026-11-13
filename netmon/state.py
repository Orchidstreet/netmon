# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared in-memory state: the stop flag, the logger, live readings and the database writer handle.

Touches: nothing outside the process.

Every collector thread writes its latest reading here; the API reads it for the live views.
DBW is the single database writer, set by main.start() before any thread runs.
"""
import collections
import datetime
import logging
import threading

from .config import CFG

STOP = threading.Event()
LOG = logging.getLogger("netmon")
RANGES = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000, "1y": 31536000}
DBW = None


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.vitals = None                                  # latest parsed router vitals
        self.vitals_ts = 0
        self.trace = collections.deque(maxlen=1080)         # (ts, down_bps, up_bps), 3 h at 10 s
        self.router_trace = collections.deque(maxlen=1080)  # (ts, cpu, temp)
        self.feed_ts = 0                                    # time of the last traffic batch
        self.feed_status = "starting"
        self.protos = {}
        self.latency = {}                                   # target -> latest dict
        self.router_hot = False                             # router past its protection limits
        self.minute = collections.defaultdict(list)
        self.live_dns = collections.deque(maxlen=400)       # most recent lookups from the DNS source
        self.dns_source = {"name": "dnsmasq", "status": "starting", "ts": 0}
        self.links = {}                                     # mac -> link facts (wired or Wi-Fi, signal, port)
        self.ports = {}                                     # router wired port -> speed, best speed, errors, macs


S = State()


def span(q, default="24h"):
    return RANGES.get(q.get("range", default), RANGES[default])


def _tz():
    name = CFG["site"].get("tz")
    if name:
        try:
            from zoneinfo import ZoneInfo
            return ZoneInfo(name)
        except Exception:
            return None
    return None


def fmt_time(ts):
    """'14:02 (UTC 13:02) on 3 Mar 2026' in the site's time zone, for human text."""
    utc = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    tz = _tz()
    loc = utc.astimezone(tz) if tz else utc.astimezone()
    return f"{loc:%H:%M} (UTC {utc:%H:%M}) on {loc.day} {loc:%b %Y}"


def short_time(ts):
    """'14:02' in the site's time zone, or '?'."""
    if not ts:
        return "?"
    tz = _tz()
    t = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    return f"{(t.astimezone(tz) if tz else t.astimezone()):%H:%M}"


ACTION_LOCK = threading.Lock()


def claim(state):
    """Sets state["busy"] only if it was free, atomically. Returns True when this caller now holds it."""
    with ACTION_LOCK:
        if state["busy"]:
            return False
        state["busy"] = True
        return True
