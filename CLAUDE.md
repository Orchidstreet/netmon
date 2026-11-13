# Netmon: notes for a Claude Code session

Netmon is a network monitor. A collector (Python, standard library only) talks to a site's router through a
restricted SSH command gate, stores flows, devices, DNS lookups and latency in SQLite, runs checks, and serves
a plain-JavaScript web interface of about forty pages. Licence: AGPL-3.0-or-later.

## Layout

- `netmon.py`: thin entry point. `python3 netmon.py [--config FILE]`, or `--check-config FILE`.
- `netmon/`: the collector package, one job per module, each with a header docstring saying what it touches.
  - `config.py` loads `config.json` into `CFG`, fills defaults, validates, and builds the `site` block.
  - `db.py` SQLite schema, the single writer, readers, retention.
  - `router.py` everything that talks to the router (`netmon-gate` over SSH).
  - `collect.py` the loops: netifyd feed, vitals, conntrack, leases, links.
  - `dns.py` the DNS source (dnsmasq log through the gate).
  - `checks.py` scheduled checks. `alerts.py` email alerts. `heal.py` every action that changes the network,
    each behind a config switch.
  - `api.py` the HTTP server, access rules and every `/api` route; `views*.py` and `vpn.py` build the replies.
  - `geo.py` DB-IP lookups from local files. `classify.py` names for devices, apps and destinations.
  - `capture.py` short packet captures; `health.py` machine health and self-test results; `state.py` shared state;
    `main.py` start-up.
- `dpi.py`: packet fingerprinting for the Fingerprints page.
- `router/`: what runs on the OpenWrt router: `netmon-gate`, `gate.conf.example`, the VPN DNS helper, the
  watchdog, firewall includes, the sysupgrade list and a crontab example.
- `selftest/`: the self-test (`selftest.py`), its fixtures and its schedulers.
- `health/`: the machine-health reporter script.
- `web/`: the interface. `index.html`, `app.js` (all pages), `app.css`, `land.js` (globe data), `doh.js`
  (known encrypted-DNS hosts). Names of the site's equipment come from `NOW.site`, never from the code.
- `docs/`: `INSTALL.md`, `ADAPTING.md` (the gate's subcommands and formats), `ARCHITECTURE.md`.
- `SECURITY.md` threat model. `scan.sh` personal-data scan.

## Checks to run

```
./scan.sh                                          # must print nothing and exit 0
python3 -m py_compile netmon.py dpi.py netmon/*.py selftest/*.py
for f in web/*.js; do node --check "$f"; done
python3 netmon.py --check-config config.example.json   # must exit 0
python3 selftest/selftest.py quick                 # code, endpoints and locks; needs a running collector
```

`scan.sh` has built-in patterns (emails, home-folder paths, private keys) and reads the operator's private
deny list from `scan.deny` (git-ignored) or `$NETMON_DENY`. The header of `scan.sh` explains the format.

To try the interface without a router, run the collector with the example config and a scratch data folder:
`NETMON_DATA_DIR=/tmp/netmon-try python3 netmon.py --config config.example.json`, then open
http://127.0.0.1:7780/. Every page should show empty states, not errors.

## Task: review this for security

1. Read `SECURITY.md`: what is stored, what is reachable, what the switches do.
2. Read `netmon/router.py`: every command sent to the router. Confirm that only `vpn on` and `vpn off` change it.
3. Read `netmon/alerts.py`: the only outbound mail. Check where the SMTP password comes from.
4. Read `netmon/heal.py`: every action that changes the network. Confirm each one checks its switch.
5. Read `router/netmon-gate`: the subcommand list, the source-address check, argument checks, limits and locks.
   Try to find input that reaches a shell, a path outside the allowed ones, or a longer capture.
6. Read the access rules at the top of `netmon/api.py`: the allow list, the Host check, the POST header and
   Origin checks, and the two health endpoints that use tokens instead.
7. Grep for anything else that opens a socket or runs a process (`subprocess`, `socket`, `urllib`, `smtplib`)
   and confirm it is one of the above.
8. Report findings with file and line, and say what was checked and how.

## Task: adapt this to my router

1. Read `docs/ADAPTING.md`: each gate subcommand, its input, its output format and what it needs on the router.
2. For another OpenWrt router: edit `router/gate.conf.example` into `/etc/netmon/gate.conf` (allowed source
   address, WAN interface, LAN bridges, ports, VPN backend) and follow `docs/INSTALL.md`.
3. For another platform (OPNsense, VyOS, MikroTik): write a gate for it that answers the same subcommands in
   the same formats. Start with `vitals`, `conns`, `leases` and `dnslog`; the others can answer
   a refusal line such as `{"gate":"no-dnslog"}` with exit code 6 until they exist (`docs/ADAPTING.md` lists the reasons).
4. Copy `config.example.json` to `config.json` and fill in `site`, `router` (name, ip, ssh, gate path,
   wan_iface, lan_bridges), `uplink`, `isp`, `zones`, `dns`, `latency_targets` and `vpn`.
5. Run `python3 netmon.py --check-config config.json`, start the collector, and run the self-test.
6. Keep your own names and addresses out of the repository: they belong in `config.json`, which git ignores.
   Add them to your `scan.deny` so `scan.sh` catches any that slip into a file.

## Rules

- No personal data in the repository: no names, addresses, emails, hostnames, MACs, tokens, keys or
  home-folder paths of a real network. Examples use RFC 5737 addresses and invented names.
- `./scan.sh` must pass before any commit.
- Comments say what the code does, in the present tense. No dates, names or history.
- Every source file starts with an `SPDX-License-Identifier: AGPL-3.0-or-later` line.
