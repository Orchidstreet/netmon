# Security

This file states what Netmon holds, what it can reach, what stops it, and how to report a problem.
A reviewer can check every claim here against three files: `netmon/router.py`, `netmon/alerts.py` and
`netmon/heal.py`. Every outbound action the collector can take lives in one of them.

## What the collector stores

All data stays on the collector, in `<data_dir>/netmon.db` (SQLite) and a few cache files beside it.

- Flow records from the router's netifyd feed: device, destination address and port, application, bytes.
- Device records: card address (MAC), IP address, hostname, vendor, the label you give it, first and last seen.
- DNS lookups from the router's dnsmasq log: time, client, name, type, how it was answered.
- Router vitals, latency samples, check results, events, machine-health reports, self-test results.
- Short packet captures are fingerprinted in memory (first bytes, sizes, timing) and are not written to disk.

This is sensitive data about the people on the network. Treat the collector's disk and its backups that way.
Old rows are deleted after `retention_days`.

## What the collector can reach

- **The router**, over SSH, with one key. The router's `authorized_keys` entry names `netmon-gate` as the key's
  forced command, so the key runs the gate and nothing else: no shell, no port forwarding, no agent, no pty.
  The gate accepts only its listed subcommands (feed, vitals, conns, leases, protos, apps, links, capture,
  ispview, dnslog, cake, health, integrity, vpn status, vpn on, vpn off). Only `vpn on` and `vpn off` change
  the router.
- **The internet**, only for what you configure: the latency targets you list, and the checks you define.
  Geography comes from DB-IP files on disk; the lookup makes no network calls.
- **Mail**, only when `alerts.email_to` is set: one SMTP server, for alerts. The password comes from an
  environment variable by default, not from `config.json`.
- **Machines you list** under `health_machines`: they push reports to the collector. The collector does not
  log in to them.

## What changes the network

Everything that changes something sits behind a switch in `config.json`, and every switch is off by default:

- `actions.vpn_switch`: the web page may switch the router's VPN on and off.
- `actions.load_test`: the Bufferbloat page may run a 20-second full-load test from the collector.
- `heal.vpn_off_when_tunnel_down`: the collector switches the VPN off when the tunnel is on but dead.

With all switches off, the collector only reads.

## What the gate refuses

`router/netmon-gate` refuses, with a one-line JSON reason and a non-zero exit code:

- any subcommand not in its list, and any malformed argument;
- any request from a source address not in `ALLOW_FROM` in `/etc/netmon/gate.conf` (an empty list refuses all);
- every request when `gate.conf` is missing;
- captures on interfaces not in `CAPTURE_IFACES`, or longer than 30 seconds;
- work while the router is past its load, temperature or memory limits;
- a second capture or VPN change while one holds the lock, and repeats that come too fast.

Filename expansion is off for everything the caller sends.

## What the web allow list does

The web server answers only clients whose address is in `collector.allow`. It also checks the `Host` header
against the collector's own names and addresses, which stops DNS-rebinding pages from reading the API through
a browser on your network. POST requests need the header `X-Netmon: 1` and, when the browser sends one, a
matching `Origin`. The two health endpoints skip the allow list and check a per-machine token and source
address instead. The web interface has no login: the allow list is the access control, so keep it narrow.

## If the collector is compromised

An attacker with the collector's account could:

- read everything in the database: who was online, what they looked up, where their traffic went;
- use the router key to run the gate's subcommands: read the router's tables, take short captures, and switch
  the VPN on or off;
- send mail through the configured SMTP account;
- change the web pages served to the people on the allow list.

They could not, through Netmon's own access:

- open a shell on the router, change its firewall, or install anything there, because the key is pinned to
  the gate;
- capture for longer than 30 seconds at a time, or on interfaces the gate does not list;
- log in to the machines that push health reports.

Keep the collector patched, give Netmon its own user account, and keep `config.json`, `gate.conf` and the
key files readable by that user only.

## Reporting a vulnerability

Open a private security advisory on the repository's GitHub page (Security tab, "Report a vulnerability").
Please include the version or commit, what you did, and what happened. Do not open a public issue for a
security problem.
