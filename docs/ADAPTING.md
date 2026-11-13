<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Adapting netmon to another router

The collector never touches the router directly. Every request goes through one program on the router,
`netmon-gate`, which the collector's SSH key is forced to run. The gate is the whole interface between netmon
and a router. To support another router, write a program that answers the same subcommands in the same formats.
Nothing in the collector needs to change.

This file is that contract. `router/netmon-gate` is the OpenWrt implementation, and its settings come from
`/etc/netmon/gate.conf` (`router/gate.conf.example`).

## How the collector calls the gate

```
ssh <router.ssh> <router.gate> <subcommand> [arguments]
```

`router.ssh`, `router.key` and `router.gate` come from config.json. With a forced command, the router's SSH
server runs the gate whatever the client asked for, and passes the request in `SSH_ORIGINAL_COMMAND`. The gate
drops a leading word that names the gate itself, so `"/usr/bin/netmon-gate vitals"` and `"vitals"` are the same
request. One multiplexed SSH connection carries all calls.

A port needs, on the target system:

- an SSH server that supports a forced command per key (OpenSSH `command="..."` in `authorized_keys`, or a
  `ForceCommand` in a `Match` block), or another way to make one key run one program only;
- a POSIX shell or any language that can read `SSH_ORIGINAL_COMMAND` and write to stdout.

### Rules every implementation follows

- **Refuse by default.** Anything not listed below answers `{"gate":"not-allowed"}` with exit code 1.
- **Check the source.** Serve only the collector's addresses (`SSH_CLIENT`), else `{"gate":"wrong-source"}`, exit 1.
- **Never expand the request.** Split it into words; never pass it to a shell (the OpenWrt gate runs `set -f`).
- **Protect the router.** Refuse or stop heavy work when the router is overloaded (see exit code 3).
- **One line of JSON per refusal** on stdout: `{"gate":"<reason>"}`, sometimes with readings.

### Exit codes

| Code | Meaning | Sample stdout |
|---|---|---|
| 0 | success | the answer |
| 1 | refused: wrong source, not configured, not allowed, bad argument, unexpected VPN peer | `{"gate":"not-allowed"}` |
| 3 | the router is past a protection limit; streams stop with this code too | `{"gate":"refused","load_x100":412,"temp_mc":61000,"mem_avail_kb":250000}` |
| 4 | busy or rate-limited | `{"gate":"rate-limited"}`, `{"gate":"busy"}`, `{"gate":"vpn-busy"}` |
| 5 | `vpn on` saw no handshake in time and switched the VPN back off | `{"vpn":"failed-reverted"}` |
| 6 | the data source for this subcommand is not available on this router | `{"gate":"no-dnslog"}`, `{"gate":"no-vpn"}` |
| 255 | (from ssh, not the gate) the router could not be reached | |

Refusal reasons in use: `not-configured`, `wrong-source`, `not-allowed`, `bad-interface`, `bad-seconds`,
`unexpected-peer`, `busy`, `vpn-busy`, `rate-limited`, `refused`, `stopped`, `no-nc`, `no-tcpdump`, `no-apps`,
`no-dnslog`, `no-shapers`, `no-vpn`.

The protection limits in the OpenWrt gate are the 1-minute load × 100 (`LOAD_MAX`, default 300), the SoC
temperature in millidegrees (`TEMP_MAX`, 85000) and `MemAvailable` in kB (`MEM_MIN`, 60000).

---

## The subcommands

Each section lists the purpose, the input, the output with a sample, what the OpenWrt gate uses, and the
equivalent data source on OPNsense, VyOS and MikroTik RouterOS. On RouterOS no shell runs on the router: the gate
becomes a small program on another machine that reads the RouterOS API (or `/tool sniffer` and scripts) and
prints the same formats. The collector's SSH key then points at that machine.

### feed

**Purpose.** Live flows with the application and protocol each belongs to. It drives the traffic pages.
**Input.** None. It streams until the client disconnects or the router passes a protection limit (exit 3).
**Output.** netifyd's JSON stream as netifyd writes it: one JSON object per line, with `"type"` values such as
`flow`, `flow_purge` and `agent_status`. The collector reads `flow` objects for `local_ip`, `local_mac`,
`other_ip`, `other_port`, `detected_protocol_name`, `detected_application_name`, `host_server_name`, and the byte
and packet counters.

```
{"type":"flow","flow":{"local_ip":"192.168.1.23","local_mac":"02:00:5e:10:00:01","other_ip":"198.51.100.7","other_port":443,"detected_protocol_name":"HTTP/S","detected_application_name":"netify.example","host_server_name":"www.example.com",...}}
```

**OpenWrt.** `nc FEED_HOST FEED_PORT` against netifyd's socket.
**OPNsense.** netifyd is packaged for FreeBSD (the Sensei / Zenarmor engine is separate). Run netifyd with a TCP
socket and the same `nc` call. Without netifyd, a port has to emit the same `flow` objects from `pflog` or an
`ntopng` stream, which is a larger job.
**VyOS.** VyOS is Debian underneath: install netifyd from its Debian packages, or emit `flow` objects from
`conntrack -E -o extended` (no application names then).
**MikroTik.** No netifyd. Use RouterOS Traffic Flow (NetFlow v9 or IPFIX) to a collector-side converter that prints
`flow` objects; application names then come only from the server name and port.

### vitals

**Purpose.** One snapshot of the router's health, every few seconds.
**Input.** None.
**Output.** One JSON line.

```
{"ts":1794580000,"uptime":86400,"load":[0.08,0.04,0.07],"cpu":[1200,0,900,98000,40,0,300],"temp_mc":52900,"mem_total_kb":1013116,"mem_avail_kb":571976,"conntrack":[812,65536],"wifi_clients":9,"netifyd_rss_kb":48212,"dns_upstream":"9.9.9.9","ifaces":{"eth1":[10951332374,2893474896],"br-lan":[2893474896,10951332374]}}
```

`cpu` is the first seven counters of the `cpu` line in `/proc/stat` (user, nice, system, idle, iowait, irq,
softirq). `conntrack` is [entries, maximum]. `ifaces` maps each interface to [rx bytes, tx bytes]: the uplink
interface first, then each LAN bridge. `dns_upstream` is dnsmasq's first upstream server, or empty.

**OpenWrt.** `/proc/loadavg`, `/proc/stat`, `/proc/meminfo`, a thermal zone, `nf_conntrack_count`/`_max`,
`iwinfo assoclist`, `/sys/class/net/*/statistics`.
**OPNsense.** `sysctl vm.loadavg kern.cp_time hw.physmem dev.cpu.0.temperature`, `pfctl -si` for state counts
(`pfctl -sm` for the limit), `netstat -ibn` for counters. Report `cpu` in the same order, using 0 where FreeBSD
has no counter.
**VyOS.** The same Linux files as OpenWrt.
**MikroTik.** `/system resource print` (CPU load, memory, uptime), `/system health print` (temperature),
`/ip firewall connection tracking print` (count, maximum), `/interface print stats` (bytes),
`/interface wireless registration-table` or `/interface wifi registration-table` (clients).

### conns

**Purpose.** The connection tracking table: who talks to whom, and which connections leave through a tunnel.
**Input.** None. At most once every 5 s (exit 4 otherwise); at most 4000 lines.
**Output.** `conntrack -L -o extended` text, one connection per line.

```
ipv4     2 tcp      6 7438 ESTABLISHED src=192.168.1.23 dst=198.51.100.7 sport=51544 dport=443 src=198.51.100.7 dst=203.0.113.2 sport=443 dport=51544 [ASSURED] mark=0 use=1
```

The collector reads the original direction (first `src`, `dst`, `sport`, `dport`) and the reply's `dst`, which
shows whether the connection was NATed to the uplink or to a tunnel address.

**OpenWrt / VyOS.** `conntrack -L -o extended`.
**OPNsense.** `pfctl -ss -vv`; convert each state to the line format above.
**MikroTik.** `/ip firewall connection print detail`, converted to the same line format.

### leases

**Purpose.** Device names and addresses from DHCP.
**Input.** None.
**Output.** The dnsmasq lease file: `<expiry unix s> <mac> <ip> <hostname or *> <client id or *>`.

```
1794590000 02:00:5e:10:00:01 192.168.1.23 laptop-01 01:02:00:5e:10:00:01
```

**OpenWrt.** `cat /tmp/dhcp.leases`.
**OPNsense.** Kea or ISC dhcpd leases (`/var/dhcpd/var/db/dhcpd.leases`), or Dnsmasq's lease file if Dnsmasq
serves DHCP. Convert to the line format.
**VyOS.** `show dhcp server leases` (or Kea's lease CSV in VyOS 1.5), converted.
**MikroTik.** `/ip dhcp-server lease print detail`, converted.

### protos

**Purpose.** netifyd's protocol id to name table.
**Input.** None.
**Output.** `netifyd --dump-protos`, at most 2000 lines: `<id>: <name>` per line.

```
  156: HTTP/S
```

**Elsewhere.** Only needed with netifyd. Print nothing if there is no netifyd.

### apps

**Purpose.** netifyd's application list (ids, names and the domains that identify each).
**Input.** None.
**Output.** The contents of `netify-apps.conf`: lines like `app:<id>:<tag>` and `dom:<id>:<domain>`.

```
app:10119:netify.example
dom:10119:example.com
```

**Elsewhere.** Only needed with netifyd. Exit 6 with `{"gate":"no-apps"}` otherwise.

### links

**Purpose.** How each device is attached: Wi-Fi band and signal, wired port and speed, bridge.
**Input.** None.
**Output.** One fact per line, `|`-separated, in four kinds:

```
wifi|<mac>|<band, e.g. 5.180 GHz>|<signal dBm>|<tx rate Mbit/s>
arp|<mac>|<ip>|<bridge>
port|<name>|<bridge port number>|<carrier 0/1>|<speed now>|<best own speed>|<best partner speed>|<rx_errors>|<tx_errors>|<rx_dropped>|<tx_dropped>|<rx_bytes>|<tx_bytes>
fdb|<bridge>|<mac>|<bridge port number>
```

```
wifi|02:00:5e:10:00:01|5.180 GHz|-52|866.7
arp|02:00:5e:10:00:01|192.168.1.23|br-lan
port|lan1|0x1|1|1000|2500|1000|0|0|0|0|123456789|987654321
fdb|br-lan|02:00:5e:10:00:04|1
```

`port` lines give the bridge port number as the kernel shows it (`0x1`); `fdb` lines give it in decimal. The
collector matches a MAC to a port through these two numbers. Empty fields are allowed.

**OpenWrt.** `iwinfo`, `/proc/net/arp`, `ethtool`, `/sys/class/net/<port>`, `brctl showmacs` or `bridge fdb`.
**OPNsense.** `arp -an`, `ifconfig -v` (media, status), `netstat -ibn`, `ifconfig bridge0 addr` for the
forwarding table. Wi-Fi only if the box is also the access point.
**VyOS.** Linux tools as on OpenWrt; Wi-Fi through `iw dev <if> station dump`.
**MikroTik.** `/interface ethernet monitor` (speed, link), `/interface bridge host print` (fdb),
`/ip arp print`, the wireless registration table.

### capture IFACE SECONDS

**Purpose.** A short packet capture for traffic fingerprinting (`dpi.py`).
**Input.** An interface from the allowed list (`CAPTURE_IFACES`) and 5 to 30 seconds. One capture at a time
(exit 4, `busy`), at most one a minute (exit 4, `rate-limited`).
**Output.** A pcap stream on stdout: 256 bytes per packet, at most 40 000 packets, never the SSH port.

**OpenWrt / VyOS.** `timeout SECONDS tcpdump -i IFACE -s 256 -c 40000 -U -w - not port 22`.
**OPNsense.** The same `tcpdump` (FreeBSD has it in base).
**MikroTik.** `/tool sniffer` with `file-name` or streaming to a TZSP receiver on another machine, which writes
the pcap.

### ispview SECONDS

**Purpose.** What the ISP can see: handshake packets on the uplink side, whole, so server names can be read.
**Input.** 5 to 30 seconds. Shares the capture lock and rate limit.
**Output.** A pcap stream of the uplink interface with this filter: QUIC long headers, TLS handshake records,
HTTP requests, connection openings (SYN), plain DNS and WireGuard handshakes. 1600 bytes per packet, at most
20 000 packets.

**Elsewhere.** The same `tcpdump` filter on the uplink interface (`router/netmon-gate` holds the exact filter).

### dnslog

**Purpose.** Every DNS lookup on the network: who asked for which name, and what happened.
**Input.** None. It follows the log from its end and streams until the client disconnects or the router passes
a protection limit.
**Output.** One JSON object per lookup:

```
{"ts":1794580001,"client":"192.168.1.23","domain":"example.com","qtype":"A","status":"forwarded","answers":["198.51.100.7"]}
{"ts":1794580002,"client":"192.168.1.40","domain":"ads.example.net","qtype":"A","status":"blocked"}
```

| Key | Type | Meaning |
|---|---|---|
| `ts` | integer | Unix seconds |
| `client` | string | the asking device's address |
| `domain` | string | the name asked for |
| `qtype` | string | `A`, `AAAA`, `HTTPS`, ... or `TYPE<n>` for types dnsmasq does not name |
| `status` | string | `forwarded` (sent upstream), `cached` (answered from cache), `blocked` (answered `0.0.0.0`, `::` or `NXDOMAIN` by a block list or configuration), `other` (local names, DHCP names, no outcome seen) |
| `answers` | list of strings | optional: the addresses in the answer. Left out when there are none |
| `reply_ms` | integer | optional: milliseconds from query to reply. The OpenWrt gate leaves it out, because dnsmasq logs times to the second only |

The OpenWrt gate prints a forwarded or cached lookup once its answer lines are in (or after 3 s), so lines can
arrive slightly out of order. Answers are matched most reliably with dnsmasq's `log-queries=extra`, which tags
every line with the lookup's serial number. Without it, lines are matched by name, and an answer reached through
a CNAME is not attached.

**OpenWrt.** dnsmasq with `logqueries` and `logfacility=/tmp/dnsmasq.log`; `tail -F` into an awk parser.
**OPNsense.** Unbound: set `log-queries: yes` and `log-replies: yes` and follow `/var/log/resolver/latest.log`;
Unbound's reply lines carry the client, the name, the type, the return code and the time taken, so `reply_ms`
is available. Dnsmasq on OPNsense works as on OpenWrt.
**VyOS.** VyOS's DNS forwarding is PowerDNS Recursor. Its setting `quiet=no` logs each incoming query (client,
name, type) but not the outcome; for a status per lookup, use the Recursor's protobuf logging, or capture port 53
with `tcpdump` and decode it.
**MikroTik.** `/system logging add topics=dns` sends query lines to a remote syslog server. The gate on the
other machine reads that syslog stream and prints the same JSON. RouterOS logs no reply status, so `status` is
`forwarded` or `cached` as far as the log says, and `other` otherwise.

### cake

**Purpose.** CAKE shaper counters for the bufferbloat pages.
**Input.** None.
**Output.** For each device in `SHAPER_DEVS`: a line `## <device>`, then `tc -s qdisc show dev <device>` from
the `qdisc cake` line on (the tin table with Bulk, Best Effort, Video and Voice columns).
`selftest/fixtures/cake.txt` is a full sample.

**OpenWrt / VyOS.** `tc -s qdisc`. On VyOS, CAKE is a traffic policy (`set qos policy cake`).
**OPNsense.** No CAKE; FQ-CoDel through `ipfw`/dummynet. Print nothing and exit 6 (`no-shapers`), or emit the
same layout from `ipfw sched show` with one tin.
**MikroTik.** RouterOS 7 queues support `cake` as a queue type; `/queue simple print stats` or
`/queue tree print stats`, converted to the same layout with one tin.

### health

**Purpose.** The router's row on the Machine health page.
**Input.** None.
**Output.** One fact per line, `kind|field|field...`, the same format as `health/netmon-health.sh`:

```
v|1|1794580000
host|edge-01|edge-01
os|OpenWrt 23.05.5 r24106-10cc5fcd00|5.15.167
model|Example Networks EX-6000|4 cores
uptime|60003
load|0.08|0.04|0.07
mem|1013116|571976|
disk|/overlay|flash|7008876|522284|6486592
temp|cpu-thermal|52.9
net|eth1|10951332374|2893474896
addr|br-lan|192.168.1.1|02:00:5e:00:00:01
updc|opkg|2|1794560000|iperf3 dnsmasq-full
posture|ssh_password_auth|off
```

**Elsewhere.** The same kinds from the platform's own tools: `pkg version -l '<'` (OPNsense),
`apt list --upgradable` (VyOS images are replaced whole, so report 0), `/system package update check-for-updates`
(MikroTik).

### integrity

**Purpose.** Facts the self-test compares with a blessed copy, so a lost router setting shows by itself.
**Input.** None.
**Output.** One fact per line:

```
v|1|<unix s>
file|<path>|<sha256 or missing>|<1 if a firmware upgrade keeps it, else 0>
sqm|<section>|<interface>|<enabled>|<download kbit/s>|<upload kbit/s>|<overhead>|<script>
qdisc|<device>|<bandwidth, e.g. 40Mbit>|<diffserv mode>
ctinfo|<device>|<number of ctinfo filters>
mangle|<chain>|<rules>|<hooks>
prio_pkts|<packets marked>
l2block|<bridge drop rules>
natdns|<DNS redirect rules>
cron|watchdog|<1 if scheduled>
vpndns|<netmon-vpn-dns.sh status JSON>
```

**Elsewhere.** Hash the port's own files and report the shaper settings in the same kinds. Kinds the platform
does not have can be left out; the self-test skips what it was never blessed with.

### vpn status | vpn on | vpn off

**Purpose.** Read and switch a VPN that carries the whole network's traffic. `vpn on` and `vpn off` are the
only subcommands that change the router; the collector sends them only when `actions.vpn_switch` or
`heal.vpn_off_when_tunnel_down` is set in config.json.
**Input.** None. One change at a time (exit 4, `vpn-busy`).
**Output.**

```
vpn status → {"backend":"uci","enabled":"1","rule":"1","peer":"","handshake":1794579990,"transfer":[123456789,9876543],"now":1794580000,"dns":{"want":"tunnel","have":"tunnel","vpn_resolver":true,"ok":true},"endpoint":"203.0.113.50:51820"}
vpn on     → {"vpn":"on","after":4,"dns":{...}}            or {"vpn":"failed-reverted"} with exit 5
vpn off    → {"vpn":"off","dns":{...}}
```

`enabled` and `rule` are `"1"` when the switch is on (the GL.iNet backend reports its global switch and rule 0
separately). `handshake` is the WireGuard peer's latest handshake in Unix seconds, 0 for none. `transfer` is
[rx, tx] bytes. `dns` is the VPN-aware DNS state, or `null`. `vpn on` waits up to `VPN_UP_WAIT` seconds for a
fresh handshake and switches back off without one.

**OpenWrt.** Backends `uci` (`network.<iface>.disabled`, `ifup`/`ifdown`, `wg show`) and `glinet`
(`route_policy`, `/etc/init.d/vpn-client`). With `VPN_BACKEND=none`, `on` and `off` exit 6.
**OPNsense.** `configctl wireguard restart` after toggling the instance in `config.xml`, or
`configctl interface reconfigure`; `wg show` works on FreeBSD.
**VyOS.** `set interfaces wireguard wgN disable` / `delete ... disable` in a `configure` session through
`/opt/vyatta/bin/vyatta-op-cmd-wrapper` or the HTTP API; `wg show` for the handshake.
**MikroTik.** `/interface wireguard set [find name=wg1] disabled=no|yes`; the peer's `last-handshake` from
`/interface wireguard peers print detail`.

---

## Other router-side parts

These are optional and specific to OpenWrt. Each reads `/etc/netmon/gate.conf`.

| File | What it does | Equivalent elsewhere |
|---|---|---|
| `netmon-vpn-dns.sh` | Redirects LAN DNS to a resolver inside the tunnel while the VPN is on (iptables NAT) | OPNsense: a port-forward rule toggled with the VPN; MikroTik: a `dst-nat` rule toggled by a script |
| `firewall.netmon_vpn_dns` | Re-syncs the redirect on each firewall reload | not needed where rules persist |
| `firewall.netmon_prio` | Marks chosen devices' traffic DSCP AF41 and restores it on downloads with `tc ctinfo` | OPNsense: shaper rules by MAC; MikroTik: mangle `change-dscp` and queue priorities |
| `firewall.netmon_l2block` | Drops all frames from and to chosen MACs at the bridge (nftables bridge table) | OPNsense: a filter on the bridge; MikroTik: `/interface bridge filter` |
| `netmon-watchdog.sh` | Renegotiates a wired port that lost carrier and stays down | MikroTik: a netwatch or scheduler script with `/interface ethernet reset-counters` and disable/enable |

## Assumptions in the OpenWrt gate

- Linux paths: `/proc`, `/sys/class/net`, `/sys/class/thermal/thermal_zone0`.
- BusyBox tools: `flock`, `timeout`, `nc`, `tail -F`, and an `awk` whose `srand()` returns the previous seed
  (used as the clock in `dnslog`).
- Dropbear sets `SSH_CLIENT` and `SSH_ORIGINAL_COMMAND`.
- `iwinfo` for Wi-Fi; `WIFI_IFACES` names MediaTek interfaces such as `ra0` on GL.iNet firmware.
- `iptables` (fw3, or iptables-nft on fw4) for `integrity`'s `mangle` and `natdns` lines and for the
  includes; `CONNMARK --set-dscpmark` is an OpenWrt extension.
- `sysupgrade -l` lists the files a firmware upgrade keeps; `opkg` lists updates.
- The `glinet` VPN backend uses GL.iNet's `route_policy` config and `/etc/init.d/vpn-client`, which exist only
  on GL.iNet firmware.

## Configuration keys the collector reads

`config.example.json` shows the common keys. The collector also reads these, each with a default in
`netmon/config.py`: `router.key`, `router.ssh_options`, `router.limits`, `collector.bind`, `collector.hosts`,
`dns.filter_name`, `dns.server`, `vpn.provider_org`, `vpn.api_domains`, `vpn.hosters`, `actions`, `heal`,
`adapters`, `companies`, `threats`, `dpi`, `selftest` (`data_dir`, `queue_dir`, and the self-test's own keys
listed at the top of `selftest/selftest.py`), `bloat`. The Self-test page's Run now button writes a file named
`run-now` into `selftest.queue_dir`; the scheduler starts a run when that folder is not empty.

Fixtures and examples use the ranges `192.168.1.0/24` (LAN), `192.168.20.0/24` (a fenced IoT zone) and the
documentation ranges `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`.

## One probe per site, reporting to a primary

**Not built yet.** Today one collector serves one router. The parts that exist:

- The gate interface is already remote: a collector at one site can reach a router at another over any SSH path
  (a VPN between sites, for example). That gives one collector per router, each with its own web interface.
- `config.json` has one `site`, one `router` and one database.

What a multi-site design needs, and where it would go:

1. **A probe** per site: the collector with the web server off, writing its rows into its local database as
   now.
2. **A push** from each probe to the primary: batches of rows per table since the last acknowledged time, over
   HTTPS with a per-probe token, in the same way `/api/health/report` accepts reports per machine today.
3. **A site column** in every table on the primary, and a `sites` list in its config.json in place of the single
   `site` and `router`.
4. **A site picker** in the web interface, with every `/api` route taking a `site` parameter.

Until then, run one collector per site and open each one's interface.
