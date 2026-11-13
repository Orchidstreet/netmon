# SPDX-License-Identifier: AGPL-3.0-or-later
"""Start-up: reads the command line, loads and checks the config, prepares the data folder, starts
every collector thread and the web server, and stops them cleanly on SIGTERM or SIGINT.

Touches: the data folder (database, logs, caches); starts the threads listed in LOOPS.

Usage:
  python3 netmon.py [--config FILE]        run (default FILE: config.json next to netmon.py)
  python3 netmon.py --check-config FILE    validate FILE, print the result, exit 0 or 1
The environment variable NETMON_DATA_DIR overrides collector.data_dir.
"""
import argparse
import faulthandler
import logging
import logging.handlers
import os
import signal
import sys
import threading
import time

from . import config, state
from .config import CFG
from .state import LOG, STOP, S


def check_config(path):
    """Prints a readable verdict and returns the process exit code."""
    try:
        merged, raw = config.read(path)
    except FileNotFoundError:
        print(f"{path}: file not found", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"{path}: not valid JSON: {e}", file=sys.stderr)
        return 1
    errs = config.validate(merged, raw)
    unknown = sorted(set(raw) - set(config.DEFAULTS))
    if errs:
        print(f"{path}: {len(errs)} problem{'s' if len(errs) > 1 else ''}:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"{path}: OK. Site \"{merged['site'].get('name')}\", router {merged['router'].get('name')} at "
          f"{merged['router'].get('ip')}, web interface on port {merged['collector']['port']}.")
    if unknown:
        print(f"  note: keys not used by netmon: {', '.join(unknown)}")
    return 0


def prepare_data_dir():
    """Creates the data folder. When the configured one cannot be written, uses a folder in the
    user's home and says so in the log."""
    want = os.environ.get("NETMON_DATA_DIR") or CFG["collector"]["data_dir"]
    wait_for = CFG["collector"].get("wait_for")
    while wait_for and not os.path.isdir(wait_for) and not STOP.is_set():
        print(f"waiting for {wait_for}", file=sys.stderr, flush=True)
        time.sleep(15)
    for d in (want, os.path.join(os.path.expanduser("~"), ".local", "share", "netmon")):
        try:
            os.makedirs(os.path.join(d, "logs"), exist_ok=True)
            test = os.path.join(d, ".write-test")
            open(test, "w").close()
            os.remove(test)
        except OSError:
            continue
        if d != want:
            print(f"data folder {want} is not writable; using {d}", file=sys.stderr, flush=True)
        CFG["collector"]["data_dir"] = d
        return d
    raise SystemExit(f"no writable data folder (tried {want})")


def setup_logging():
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(threadName)s %(message)s")
    h = logging.handlers.RotatingFileHandler(os.path.join(config.data_dir(), "logs", "netmon.log"),
                                             maxBytes=5_000_000, backupCount=5)
    h.setFormatter(fmt)
    LOG.addHandler(h)
    e = logging.StreamHandler(sys.stderr)
    e.setFormatter(fmt)
    LOG.addHandler(e)
    LOG.setLevel(logging.INFO)


def loops():
    from . import capture, checks, classify, collect, db, dns, geo, heal, health, vpn
    return (collect.feed_loop, collect.vitals_loop, collect.conns_loop, collect.leases_loop, collect.links_loop,
            collect.latency_loop, collect.bloat_loop, dns.dns_loop, checks.checks_loop, db.prune_loop,
            classify.apps_list_loop, classify.rdns_loop, geo.geo_loop, capture.dpi_loop, vpn.tunnel_loop,
            health.health_loop, heal.heal_loop)


def run(path):
    from . import api, classify, db, router
    config.load(path)
    errs = config.validate(CFG)
    if errs:
        for e in errs:
            print(f"config: {e}", file=sys.stderr)
        return 1
    prepare_data_dir()
    setup_logging()
    try:
        faulthandler.register(signal.SIGUSR1, file=open(os.path.join(config.data_dir(), "logs", "stacks.txt"), "a"),
                              all_threads=True)
    except (AttributeError, ValueError):
        pass
    classify.load_oui()
    w = db.DB()
    w.migrate()
    state.DBW = w
    now = int(time.time())
    if w.meta("apps_baseline_until") is None:
        w.set_meta("apps_baseline_until", now + 900)
    classify.APPS_SEEN.update(x[0] for x in w.w.execute("SELECT app FROM app_seen"))
    if w.meta("baseline_until") is None:
        w.set_meta("baseline_until", now + 900)
        LOG.info("first run: devices seen in the next 15 minutes count as known")
    LOG.info("netmon starting for site %s, data in %s", CFG["site"].get("name"), config.data_dir())
    for ts, dn, up in w.w.execute("SELECT ts, down, up FROM vitals_min WHERE ts >= ? ORDER BY ts", (now - 3 * 3600,)):
        S.trace.append((ts + 30, dn, up))
    srv = api.make_server()
    threading.Thread(target=srv.serve_forever, name="http", daemon=True).start()
    LOG.info("web interface on port %s", CFG["collector"]["port"])
    if not router.probe():
        LOG.warning("router %s does not answer yet; collectors keep retrying", CFG["router"]["ip"])
    for fn in loops():
        threading.Thread(target=fn, args=(w,), name=fn.__name__, daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *a: STOP.set())
    signal.signal(signal.SIGINT, lambda *a: STOP.set())
    while not STOP.is_set():
        STOP.wait(1)
    srv.shutdown()
    LOG.info("netmon stopped")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="netmon", description="Network monitor for an OpenWrt router.")
    p.add_argument("--config", default=os.path.join(config.ROOT, "config.json"), help="config file (default: config.json)")
    p.add_argument("--check-config", metavar="FILE", help="validate FILE and exit 0 (valid) or 1 (problems)")
    a = p.parse_args(argv)
    if a.check_config:
        return check_config(a.check_config)
    if not os.path.isfile(a.config):
        print(f"{a.config}: file not found. Copy config.example.json to config.json and edit it.", file=sys.stderr)
        return 1
    return run(a.config)
