# SPDX-License-Identifier: AGPL-3.0-or-later
"""SQLite storage: schema, the single writer, read-only readers, and the retention pruner.

Touches: <data_dir>/netmon.db (and its -wal file). Nothing else.

One writer connection sits behind a lock (DB); every reader opens its own read-only connection
(reader()). prune_loop deletes rows older than the retention settings and keeps the file under
the size cap by dropping the oldest day of detail first.
"""
import os
import sqlite3
import threading
import time

from . import config
from .state import LOG, STOP, fmt_time

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS device(
  mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, label TEXT, vendor TEXT,
  first_seen INT, last_seen INT, known INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS app_15s(ts INT, mac TEXT, ip TEXT, app TEXT, proto INT,
  down INT, up INT, pkts INT);
CREATE INDEX IF NOT EXISTS app_15s_ts ON app_15s(ts);
CREATE INDEX IF NOT EXISTS app_15s_mac ON app_15s(mac, ts);
CREATE TABLE IF NOT EXISTS app_min(ts INT, mac TEXT, app TEXT, down INT, up INT, pkts INT,
  PRIMARY KEY(ts, mac, app)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS app_min_mac ON app_min(mac, ts);
CREATE TABLE IF NOT EXISTS vitals_min(ts INT PRIMARY KEY, down REAL, up REAL, down_max REAL,
  up_max REAL, cpu REAL, cpu_max REAL, temp REAL, mem_avail INT, conntrack INT, wifi INT,
  load1 REAL);
CREATE TABLE IF NOT EXISTS latency_min(ts INT, target TEXT, rtt_min REAL, rtt_med REAL,
  rtt_max REAL, loss REAL, PRIMARY KEY(ts, target)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS conn(k TEXT PRIMARY KEY, first INT, last INT, proto TEXT, src TEXT,
  sport INT, dst TEXT, dport INT, bytes_up INT, bytes_down INT, state TEXT, redir INT);
CREATE INDEX IF NOT EXISTS conn_last ON conn(last);
CREATE INDEX IF NOT EXISTS conn_src ON conn(src, last);
CREATE TABLE IF NOT EXISTS dns(ts INT, client TEXT, domain TEXT, qtype TEXT, status TEXT,
  status_code INT, reply_ms REAL, upstream TEXT);
CREATE INDEX IF NOT EXISTS dns_ts ON dns(ts);
CREATE INDEX IF NOT EXISTS dns_client ON dns(client, ts);
CREATE TABLE IF NOT EXISTS ip_name(ip TEXT PRIMARY KEY, domain TEXT, last INT);
CREATE TABLE IF NOT EXISTS check_state(name TEXT PRIMARY KEY, state INT, hard INT,
  attempts INT, since INT, last_run INT, output TEXT);
CREATE TABLE IF NOT EXISTS event(ts INT, kind TEXT, subject TEXT, state INT, text TEXT);
CREATE INDEX IF NOT EXISTS event_ts ON event(ts);
CREATE TABLE IF NOT EXISTS link_min(ts INT, mac TEXT, kind TEXT, band TEXT, signal INT, rate INT,
  port TEXT, port_speed INT, PRIMARY KEY(ts, mac)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS rdns(ip TEXT PRIMARY KEY, name TEXT, ts INT);
CREATE TABLE IF NOT EXISTS app_seen(app TEXT PRIMARY KEY, first INT, first_mac TEXT);
CREATE TABLE IF NOT EXISTS health_min(ts INT, machine TEXT, k TEXT, v REAL, PRIMARY KEY(ts, machine, k)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS cake_min(ts INT, dev TEXT, tin INT, bytes INT, drops INT, marks INT, av_us REAL, pk_us REAL,
  PRIMARY KEY(ts, dev, tin)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bloat_test(ts INT PRIMARY KEY, result TEXT);
CREATE TABLE IF NOT EXISTS tunnel_min(ts INT PRIMARY KEY, vpn_on INT, vpn_up INT, hs_age INT, rx REAL, tx REAL,
  n_tunnel INT, n_direct INT, n_local INT);
"""

# Columns added after the first schema; applied to an older database file on start.
LATE_COLUMNS = (("dns", "status_code INT"), ("dns", "reply_ms REAL"), ("dns", "upstream TEXT"), ("conn", "redir INT"))


class DB:
    """One writer connection behind a lock; readers open their own."""

    def __init__(self, path=None):
        self.path = path or config.db_path()
        self.lock = threading.Lock()
        new = not os.path.exists(self.path)
        self.w = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        if new:
            self.w.execute("PRAGMA auto_vacuum=INCREMENTAL")
        self.w.executescript(SCHEMA)
        self.w.execute("PRAGMA synchronous=NORMAL")
        self.w.commit()

    def migrate(self):
        for table, col in LATE_COLUMNS:
            try:
                self.w.execute(f"ALTER TABLE {table} ADD COLUMN {col}")
            except sqlite3.OperationalError:
                pass
        self.w.commit()

    def run(self, sql, args=()):
        with self.lock:
            cur = self.w.execute(sql, args)
            self.w.commit()
            return cur

    def many(self, sql, rows):
        if not rows:
            return
        with self.lock:
            self.w.executemany(sql, rows)
            self.w.commit()

    def one(self, sql, args=()):
        with self.lock:
            return self.w.execute(sql, args).fetchone()

    def meta(self, k, default=None):
        r = self.one("SELECT v FROM meta WHERE k=?", (k,))
        return r[0] if r else default

    def set_meta(self, k, v):
        self.run("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))

    def event(self, ts, kind, subject, state, text):
        self.run("INSERT INTO event(ts, kind, subject, state, text) VALUES(?,?,?,?,?)", (ts, kind, subject, state, text))


def reader():
    """A read-only connection with rows addressable by column name. Use it in a `with` block."""
    c = sqlite3.connect(f"file:{config.db_path()}?mode=ro", uri=True, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def db_bytes():
    p = config.db_path()
    return sum(os.path.getsize(x) for x in (p, p + "-wal") if os.path.exists(x))


DETAIL_TABLES = (("app_15s", "ts"), ("dns", "ts"), ("conn", "last"), ("ip_name", "last"), ("rdns", "ts"))
MINUTE_TABLES = (("app_min", "ts"), ("vitals_min", "ts"), ("latency_min", "ts"), ("link_min", "ts"), ("event", "ts"),
                 ("tunnel_min", "ts"), ("cake_min", "ts"), ("health_min", "ts"))


def prune_loop(db):
    """Every 5 minutes: delete rows past retention, then trim whole days until the file is under the cap."""
    while not STOP.is_set():
        STOP.wait(300)
        if STOP.is_set():
            break
        try:
            detail_days, minute_days, cap_gb = config.retention()
            now = int(time.time())
            d_cut, m_cut = now - detail_days * 86400, now - minute_days * 86400
            for t, col in DETAIL_TABLES:
                db.run(f"DELETE FROM {t} WHERE {col} < ?", (d_cut,))
            for t, col in MINUTE_TABLES:
                db.run(f"DELETE FROM {t} WHERE {col} < ?", (m_cut,))
            cap = cap_gb * 1e9
            for _ in range(400):
                if db_bytes() < cap:
                    break
                oldest = db.one("SELECT min(ts) FROM app_15s")[0]
                if oldest:
                    for t, col in (("app_15s", "ts"), ("dns", "ts"), ("conn", "last")):
                        db.run(f"DELETE FROM {t} WHERE {col} < ?", (oldest + 86400,))
                else:
                    oldest = db.one("SELECT min(ts) FROM app_min")[0] or now
                    db.run("DELETE FROM app_min WHERE ts < ?", (oldest + 86400,))
                db.run("PRAGMA incremental_vacuum(20000)")
                LOG.warning("size cap: pruned one day before %s", fmt_time(oldest))
            db.run("PRAGMA incremental_vacuum(5000)")
            with db.lock:
                db.w.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception:
            LOG.exception("prune")
