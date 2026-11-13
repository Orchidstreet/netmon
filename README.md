# Netmon

Netmon is a network monitor for people who run networks. A small collector sits at each site. It talks to the
site's router, records every flow, device, DNS lookup and latency sample in SQLite, runs health checks, and
serves a web interface of about forty pages. A site probe can report to a primary collector, so one person can
watch several sites.

It was built for OpenWrt routers. The router side is one small shell script, `router/netmon-gate`, reached over
SSH with a key that can run nothing else. Porting Netmon to another router means writing the same subcommands
for that platform; `docs/ADAPTING.md` lists them.

## What it shows

- **Now:** the internet link live, the busiest devices and applications, DNS, router vitals, latency, events.
- **Devices, Applications, Connections, DNS:** who is on the network, what they use, and every name they look up.
- **Checks and Self-test:** scheduled checks that must fail twice before they count, and a self-test of the
  collector, the router and the network every 15 minutes.
- **Topology, Airwaves, Latency, Pulse, Bufferbloat:** how each device is connected, Wi-Fi signal, round trips
  and queue delay under load.
- **Traffic, Globe, Flows, Data map, Skyline, Rhythm, Companies:** where the data goes and when.
- **Privacy radar, Beacon finder, Threat map, Fingerprints, Encryption, Ports:** heuristics that flag traffic
  worth a look, with the evidence behind each flag.
- **What the ISP sees:** a handshake-only look at the uplink, sorted by what the internet provider can read.
- **Tunnel and VPN cost:** shown only when the router's VPN is enabled in `config.json`.
- **Machine health:** disk, memory, heat, updates and security settings of the machines you choose to watch.

## What it is not

- It is not a firewall, an intrusion prevention system or an ad blocker. It observes; the only changes it can
  make to a network are behind switches that are off by default (see `SECURITY.md`).
- It is not a hosted service. Each collector keeps its data on its own disk.
- It does not decrypt traffic. Captures are short, metadata only, and are not stored.

## Requirements

- A router running OpenWrt with netifyd, dnsmasq query logging, and SSH (dropbear). Other platforms work once
  the gate's subcommands exist for them.
- A collector: a Linux or macOS machine on the same network with Python 3 and nothing beyond the standard
  library. The load test on the Bufferbloat page and the page check in the self-test use macOS tools.
- Optional: the DB-IP Lite files for geography, an SMTP account for alerts.

## Quick start

Read `docs/INSTALL.md` first. In short:

```
cp config.example.json config.json            # name your site, router, uplink, ISP and zones
python3 netmon.py --check-config config.json  # must print OK
scp router/netmon-gate root@<router>:/usr/bin/ # then gate.conf and the forced-command key, as INSTALL.md says
python3 netmon.py                              # open http://<collector>:7780/
```

## Screenshots

Screenshots will follow. Placeholders:

- `docs/screenshots/now.png`: the Now page
- `docs/screenshots/topology.png`: Topology
- `docs/screenshots/isp.png`: What the ISP sees

To try the interface without a router, use the demo repository: https://github.com/Orchidstreet/netmon-demo.
It serves the same pages over a synthetic three-site network.

## Built with Claude Code

Netmon was written with Claude Code, Anthropic's coding assistant, working with its author over many
sessions. The repository is laid out so that a Claude Code session can review it and adapt it. `CLAUDE.md`
tells a session where things live and how to run the checks. Two standard tasks are written out there:
"review this for security" and "adapt this to my router". You do not need Claude Code to run or change
Netmon; the same files serve human readers.

## Licence

Netmon is free software under the GNU Affero General Public License, version 3 or later. See `LICENSE`.
If you offer a changed version to others as a network service, the licence asks you to publish your changes.

Security problems: see `SECURITY.md`. Contributions: see `CONTRIBUTING.md`.
