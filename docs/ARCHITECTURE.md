<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Architecture

netmon is one Python process (standard library only) on a machine called **the collector**. It reads
**the router** through one restricted ssh command, stores what it sees in SQLite, runs checks, and
serves a plain-JavaScript web interface. Every name and address comes from `config.json`.

## Data flow

```
router (OpenWrt)          collector (netmon.py)                                    browser
netmon-gate  --ssh-->  router.py --> collect.py / dns.py / capture.py --> db.py --> api.py --> web/
 feed, vitals,          one ControlMaster   loops write rows and          SQLite     /api/*      pages
 conns, links,          connection,         live state (state.py)         netmon.db  /api/stream
 leases, dnslog,        one subcommand                                                (SSE)
 cake, capture ...      per call            checks.py --> alerts.py (mail)
```

1. **Router.** `router/netmon-gate` is the only program the collector's key may run. It answers a fixed
   set of subcommands (see `docs/ADAPTING.md`). The collector sends `ssh <router.ssh> <router.gate> <subcommand>`.
2. **Collector.** Threads started by `main.py` call the gate on timers, parse the output, and write rows.
3. **Database.** `db.py` holds one writer behind a lock; readers open read-only connections. `prune_loop`
   enforces `retention_days` and a size cap.
4. **API.** `api.py` serves every `/api/...` route from the route tables `GET` and `POST`, the live
   stream `/api/stream`, and the files in `web/`, to addresses on the allow list only.
5. **Web.** The pages fetch JSON. `/api/now` carries `site`, so the pages show the configured names.

## Modules (`netmon/`)

| Module | What it does |
|---|---|
| `config.py` | Loads `config.json` into `CFG`, fills defaults, validates (`--check-config`), derives site facts and the default check list. |
| `state.py` | Stop flag, logger, live readings (`S`), the database writer handle, time formatting. |
| `db.py` | Schema, the writer, readers, retention pruning. |
| `router.py` | Every command sent to the router. Tracks and logs whether the router answers. |
| `collect.py` | Traffic feed, router vitals, connection table, links and ports, DHCP leases, pings, CAKE counters. |
| `dns.py` | The DNS source: reads `netmon-gate dnslog` (one JSON line per lookup) into the `dns` table. |
| `classify.py` | Vendors (OUI), application names, the classifier's signatures, the device table, reverse DNS, company names. |
| `geo.py` | Country, owner and city of public addresses from local DB-IP Lite files. |
| `capture.py` | Short packet captures (via the gate) analysed by `dpi.py`; the view from the ISP side. |
| `vpn.py` | Tunnel state, per-device VPN status, egress counts. Reads only. |
| `checks.py` | Nagios-style checks, attempt counting, events, alert hand-off. |
| `alerts.py` | Sends mail through `alerts.smtp`; logs only when `alerts.email_to` is empty. |
| `heal.py` | Actions that change the network, each behind a switch that defaults to off. |
| `health.py` | Machine-health reports (local script, router, pushed reports) and self-test results. |
| `api.py` | HTTP server, access rules, route tables, live stream. |
| `views.py`, `views_traffic.py`, `views_security.py` | The functions behind the routes, grouped by page. |
| `main.py` | Command line, data folder, logging, thread start, clean stop. |

## What the collector can do to a network

Reading is most of the work. Three files hold every action with an effect outside the collector:

- **`router.py`**: every ssh call to the router. All subcommands are read-only except `vpn on` and
  `vpn off` (`vpn_set`), which only `heal.py` calls. Captures (`capture`, `ispview`) are read-only and
  rate-limited by the gate; `actions.captures` turns them off.
- **`alerts.py`**: sends email, and only when `alerts.email_to` is set.
- **`heal.py`**: switches the VPN on or off when `actions.vpn_switch` is true and someone presses the
  button; runs a 20-second full-load test when `actions.load_test` is true; switches a dead VPN off
  when `heal.vpn_off_when_tunnel_down` is true. All three are false by default.

Read-only probes that leave the collector: ICMP pings to `latency_targets` and check hosts, DNS
queries (`dig`) to the configured DNS server, HTTP GETs for `http` checks, and one HTTPS request to
`vpn.ip_check_url` while a VPN page is open. The web server accepts requests only from
`collector.allow`, only for its own host names, and POSTs only with the `X-Netmon: 1` header.

## Configuration switches that change behaviour

`actions.vpn_switch`, `actions.load_test`, `actions.captures`, `heal.vpn_off_when_tunnel_down`,
`vpn.enabled`, `alerts.email_to`, `checks` (replaces the default list), `retention_days`.
