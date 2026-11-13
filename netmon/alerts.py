# SPDX-License-Identifier: AGPL-3.0-or-later
"""Alerts: sends an email for a CRITICAL check, a recovery, a new device or a self-repair.

Touches: the SMTP server in CFG["alerts"]["smtp"], and only when CFG["alerts"]["email_to"] is set.
With email_to empty every alert is written to the log and nothing is sent.

Each alert has a key; the same key is sent at most once per cooldown. The SMTP password is read
from the environment variable named by smtp.password_env (NETMON_SMTP_PASSWORD by default), or
from smtp.password when the operator chose to keep it in config.json.
"""
import email.message
import os
import smtplib
import ssl
import threading
import time

from .config import CFG
from .state import LOG

_SENT = {}
_LOCK = threading.Lock()


def _due(key, cooldown):
    now = time.time()
    with _LOCK:
        if now - _SENT.get(key, 0) < cooldown:
            return False
        _SENT[key] = now
        return True


def notify(key, subject, body, cooldown=None):
    """Queues one alert. Returns at once; the mail goes out on a background thread."""
    a = CFG.get("alerts") or {}
    cooldown = a.get("cooldown_s", 1800) if cooldown is None else cooldown
    if not _due(key, cooldown):
        return
    to = (a.get("email_to") or "").strip()
    if not to:
        LOG.info("alert (log only): %s", subject)
        return
    threading.Thread(target=_send, args=(to, subject, body), name="alert", daemon=True).start()


def send_now(subject, body):
    """Sends one alert on the calling thread and returns when the mail server has accepted it or refused it."""
    to = (CFG.get("alerts") or {}).get("email_to")
    if not to:
        LOG.info("alert (no recipient configured): %s", subject)
        return False
    return _send(to, subject, body) is not False


def _send(to, subject, body):
    s = (CFG.get("alerts") or {}).get("smtp") or {}
    host = s.get("host")
    if not host:
        LOG.warning("alert not sent, alerts.smtp.host is empty: %s", subject)
        return
    msg = email.message.EmailMessage()
    msg["From"] = s.get("from") or s.get("user") or f"netmon@{host}"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    password = os.environ.get(s.get("password_env") or "NETMON_SMTP_PASSWORD") or s.get("password") or ""
    port = int(s.get("port") or 587)
    try:
        ctx = ssl.create_default_context()
        if port == 465:
            conn = smtplib.SMTP_SSL(host, port, timeout=30, context=ctx)
        else:
            conn = smtplib.SMTP(host, port, timeout=30)
            if s.get("starttls", True):
                conn.starttls(context=ctx)
        with conn:
            if s.get("user") and password:
                conn.login(s["user"], password)
            conn.send_message(msg)
        LOG.info("alert sent: %s", subject)
    except Exception as e:
        LOG.warning("alert failed (%s): %s", subject, e)
