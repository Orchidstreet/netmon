# SPDX-License-Identifier: AGPL-3.0-or-later
"""Router access: every command the collector sends to the router goes through this module.

Touches: the router, over ssh, through one restricted command (CFG["router"]["gate"], netmon-gate).

Wire format: `ssh <router.ssh> <router.gate> <subcommand> [args]`. The router's authorized_keys
entry pins the key to the gate, so the key can run nothing else. One multiplexed ssh connection
(ControlMaster) carries every call. Read-only subcommands: feed, vitals, conns, leases, protos,
apps, links, cake, health, dnslog, capture, ispview, vpn status. The only subcommands that
change the router are `vpn on` and `vpn off` (vpn_set below), called only from heal.py and only
when CFG["actions"]["vpn_switch"] or CFG["heal"]["vpn_off_when_tunnel_down"] is true.
"""
import os
import shlex
import shutil
import subprocess
import threading
import time

from .config import CFG
from .state import LOG

STATUS = {"ok": None, "since": 0, "error": ""}
_LOCK = threading.Lock()
SSH_FAILED = 255


def ssh_argv():
    r = CFG["router"]
    target = r.get("ssh") or f"root@{r['ip']}"
    argv = [shutil.which("ssh") or "/usr/bin/ssh",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=6", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
            "-o", "ControlMaster=auto", "-o", "ControlPath=/tmp/netmon-%C", "-o", "ControlPersist=600"]
    if r.get("key"):
        argv += ["-i", os.path.expanduser(r["key"]), "-o", "IdentitiesOnly=yes"]
    argv += [str(x) for x in r.get("ssh_options") or []]
    argv.append(target)
    return argv


def remote(cmd):
    """The remote command line for one gate subcommand."""
    return f"{shlex.quote(CFG['router']['gate'])} {cmd}"


def _note(rc, err=""):
    """Tracks whether the router answers and logs each change once."""
    ok = rc != SSH_FAILED
    with _LOCK:
        if ok != STATUS["ok"]:
            STATUS.update(ok=ok, since=int(time.time()), error="" if ok else (err or "").strip()[:200])
            if ok:
                LOG.info("router %s reachable", CFG["router"].get("name") or CFG["router"]["ip"])
            else:
                LOG.warning("router unreachable (%s): %s", CFG["router"]["ip"], STATUS["error"] or "ssh failed")


def gate(cmd, timeout=20):
    """Runs one gate subcommand and returns (exit code, text output). Exit code 255 means ssh failed."""
    try:
        p = subprocess.run(ssh_argv() + [remote(cmd)], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        _note(SSH_FAILED, "timed out")
        return SSH_FAILED, ""
    except OSError as e:
        _note(SSH_FAILED, str(e))
        return SSH_FAILED, ""
    _note(p.returncode, p.stderr)
    return p.returncode, p.stdout


def gate_bin(cmd, timeout=60):
    """Runs one gate subcommand and returns (exit code, raw bytes), for packet captures."""
    try:
        p = subprocess.run(ssh_argv() + [remote(cmd)], capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        _note(SSH_FAILED, "timed out")
        return SSH_FAILED, b""
    except OSError as e:
        _note(SSH_FAILED, str(e))
        return SSH_FAILED, b""
    _note(p.returncode, p.stderr.decode("utf-8", "replace"))
    return p.returncode, p.stdout


def gate_stream(cmd):
    """Starts a long-running gate subcommand (feed, dnslog) and returns the Popen; stdout is a byte pipe."""
    return subprocess.Popen(ssh_argv() + [remote(cmd)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)


def reachable():
    """True when the router is believed reachable; None before the first call."""
    return STATUS["ok"]


def probe():
    """One cheap call at start-up so the log says at once whether the router answers."""
    rc, _ = gate("vitals", timeout=15)
    return rc != SSH_FAILED


def vpn_status_raw():
    return gate("vpn status", timeout=20)


def vpn_set(on, timeout=70):
    """Switches the router's VPN on or off. Changes the router. Callers: heal.py only."""
    LOG.warning("router: vpn %s", "on" if on else "off")
    return gate("vpn on" if on else "vpn off", timeout=timeout)
