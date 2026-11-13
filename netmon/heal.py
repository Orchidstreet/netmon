# SPDX-License-Identifier: AGPL-3.0-or-later
"""Actions and self-repair: everything the collector does that changes the network, each behind a switch.

Touches: the router's VPN through router.vpn_set (`vpn on` / `vpn off`); a load test from the
collector (macOS networkQuality plus ping); alerts.py; the event, bloat_test and meta tables.

Switches, all false by default (CFG["actions"] and CFG["heal"]):
  actions.vpn_switch            the VPN page may switch the router's VPN on and off
  actions.load_test             the Bufferbloat page may run a 20-second full-load test
  heal.vpn_off_when_tunnel_down heal_loop switches the VPN off when it is on but has had no
                                handshake for heal.tunnel_down_after_s, at most once per
                                heal.min_gap_s, and sends one alert saying what it did
on_check() is the hook checks.py calls when a check changes hard state; HANDLERS maps a check
name to a repair function, and is empty unless a site adds one.
"""
import json
import re
import shutil
import subprocess
import sys
import threading
import time

from . import alerts, config, router, state
from .config import CFG
from .state import LOG, STOP, claim, fmt_time

HANDLERS = {}           # check name -> fn(db, check, old_hard, new_hard, output) -> note or None
HEAL_LOCK = threading.Lock()


def enabled(group, name):
    return bool((CFG.get(group) or {}).get(name))


def on_check(db, c, old, new, out):
    """Runs the repair registered for this check, if any, and returns a note for the check output."""
    fn = HANDLERS.get(c.get("name"))
    if not fn:
        return None
    if not HEAL_LOCK.acquire(blocking=False):
        return "A repair is already running."
    try:
        return fn(db, c, old, new, out)
    except Exception as e:
        LOG.warning("heal %s: %s", c.get("name"), e)
        return f"The repair failed to run: {e}"
    finally:
        HEAL_LOCK.release()


# ---------------------------------------------------------------- VPN switch


def vpn_switch(on):
    """Switches the router's VPN and checks that the public address changed; switches back off on failure.
    The caller has claimed VPNSW["busy"]."""
    from .vpn import VPNSW, public_ip
    label = CFG["vpn"].get("label") or "VPN"
    try:
        before = public_ip(force=True)
        rc, out = router.vpn_set(on)
        time.sleep(4)
        after = public_ip(force=True)
        res = {"ts": int(time.time()), "want": "on" if on else "off", "gate": out.strip()[:200], "ip_before": before,
               "ip_after": after}
        try:
            res["dns"] = json.loads(out).get("dns")
        except (ValueError, AttributeError):
            res["dns"] = None
        if on and (rc != 0 or not after or (before and after and after.get("ip") == before.get("ip"))):
            router.vpn_set(False, timeout=40)
            res["result"] = "failed: switched back off (" + ("no fresh handshake" if rc else "public address did not change") + ")"
        else:
            res["result"] = "on" if on else "off"
            if res["dns"] is not None and not (res["dns"] or {}).get("ok"):
                res["result"] = "on, but DNS is not going through the tunnel" if on else "off, but the DNS redirect was not fully removed"
        state.DBW.event(res["ts"], "vpn", "vpn", 1 if res["result"] == "on" else 0,
                        f"{label} for the whole site: {res['result']} (public address {((after or {}).get('ip')) or '?'})")
        VPNSW["last"] = res
        LOG.info("vpn switch: %s", res["result"])
        return res
    finally:
        VPNSW["busy"] = False


def start_vpn_switch(on):
    from .vpn import VPNSW
    if not enabled("actions", "vpn_switch"):
        return {"ok": False, "error": "switching the VPN is turned off (actions.vpn_switch in config.json)"}
    if not CFG["vpn"].get("enabled"):
        return {"ok": False, "error": "no VPN is configured (vpn.enabled in config.json)"}
    if not claim(VPNSW):
        return {"ok": False, "error": "already switching"}
    threading.Thread(target=vpn_switch, args=(bool(on),), name="vpn-switch", daemon=True).start()
    return {"ok": True}


def heal_loop(db):
    """Switches the VPN off when it is on but its tunnel has carried no handshake for too long."""
    from .vpn import TUN, VPNSW
    if not (enabled("heal", "vpn_off_when_tunnel_down") and CFG["vpn"].get("enabled")):
        return
    h = CFG["heal"]
    while not STOP.is_set():
        STOP.wait(60)
        last = TUN.get("last") or {}
        if not last.get("on") or last.get("up"):
            continue
        age = last.get("hs_age")
        if age is None or age < h.get("tunnel_down_after_s", 600):
            continue
        now = time.time()
        if now - float(db.meta("heal_vpn_last", 0) or 0) < h.get("min_gap_s", 10800):
            continue
        if not claim(VPNSW):
            continue
        db.set_meta("heal_vpn_last", int(now))
        LOG.warning("heal: VPN on but no handshake for %s s; switching it off", age)
        res = vpn_switch(False)
        label = CFG["vpn"].get("label") or "VPN"
        alerts.notify("heal-vpn", f"{config.BRAND}: {label} tunnel down, switched off",
                      f"The {label} was on but had no handshake for {age // 60} minutes at {fmt_time(int(now))}. "
                      f"{config.BRAND} switched it off so the site keeps its internet. Result: {res.get('result')}.\n\n"
                      f"{config.collector_url()}", 3600)


# ---------------------------------------------------------------- load test


def grade_for(added_ms):
    for lim, g in ((5, "A+"), (30, "A"), (60, "B"), (200, "C"), (400, "D")):
        if added_ms < lim:
            return g
    return "F"


def bloat_test_run():
    """20 s of full load from the collector (networkQuality) with a ping every 0.2 s to the first public target."""
    from .collect import BLOAT
    from .vpn import TUN
    try:
        pub = [t for t in config.latency_targets() if t["name"] in config.public_target_names()]
        host = pub[0]["host"] if pub else "1.1.1.1"
        ping = shutil.which("ping") or "ping"
        idle = subprocess.run([ping, "-i", "0.2", "-c", "15", host], capture_output=True, text=True, timeout=30).stdout
        iv = sorted(float(x) for x in re.findall(r"time=([\d.]+)", idle))
        pg = subprocess.Popen([ping, "-i", "0.2", host], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        t0 = time.time()
        nq = subprocess.run(["/usr/bin/networkQuality", "-c", "-M", "20"], capture_output=True, text=True, timeout=90).stdout
        pg.terminate()
        pout = pg.communicate(timeout=5)[0]
        lv = sorted(float(x) for x in re.findall(r"time=([\d.]+)", pout))
        sent = len(re.findall(r"icmp_seq", pout))
        j = json.loads(nq or "{}")
        med = lambda v: v[len(v) // 2] if v else None
        p90 = lambda v: v[int(.9 * (len(v) - 1))] if v else None
        idle_ms, load_p90 = med(iv), p90(lv)
        added = (load_p90 - idle_ms) if (idle_ms is not None and load_p90 is not None) else None
        res = {"ts": int(t0), "idle_ms": idle_ms, "load_med_ms": med(lv), "load_p90_ms": load_p90,
               "load_max_ms": lv[-1] if lv else None, "pings": len(lv), "lost": max(0, sent - len(lv)),
               "down_mbps": (j.get("dl_throughput") or 0) / 1e6, "up_mbps": (j.get("ul_throughput") or 0) / 1e6,
               "rpm": j.get("responsiveness"), "added_ms": added, "grade": grade_for(added) if added is not None else "?",
               "vpn": bool((TUN.get("last") or {}).get("on")), "from": CFG["collector"].get("name") or "the collector"}
        state.DBW.run("INSERT OR REPLACE INTO bloat_test VALUES(?,?)", (res["ts"], json.dumps(res)))
        BLOAT["last_test"] = res
        LOG.info("bufferbloat test: grade %s, added %s ms", res["grade"], added)
    except Exception as e:
        LOG.warning("bloat test: %s", e)
        BLOAT["last_test"] = {"ts": int(time.time()), "error": str(e)[:200]}
    finally:
        BLOAT["busy"] = False


def start_load_test():
    from .collect import BLOAT
    if not enabled("actions", "load_test"):
        return {"ok": False, "error": "the load test is turned off (actions.load_test in config.json)"}
    if sys.platform != "darwin":
        return {"ok": False, "error": "the load test needs macOS networkQuality on the collector"}
    if not claim(BLOAT):
        return {"ok": False, "error": "a test is already running"}
    threading.Thread(target=bloat_test_run, name="load-test", daemon=True).start()
    return {"ok": True, "started": int(time.time())}
