<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Installing netmon

This guide sets up one router and one collector.

- **The router** runs OpenWrt 23.05 or later with netifyd. A GL.iNet GL-MT6000 on its stock firmware also works:
  that firmware is built on OpenWrt, and the gate has a `glinet` VPN backend for it.
- **The collector** is a Linux machine or a Mac on the same network. It runs `netmon.py`, keeps the database and
  serves the web interface.

The collector talks to the router through one SSH key. The router lets that key run one program only:
`netmon-gate`, a fixed list of mostly read-only subcommands. `docs/ADAPTING.md` describes each subcommand.

The examples use these addresses. Replace them with your own.

| What | Example |
|---|---|
| Router | `192.168.1.1` |
| Collector | `192.168.1.20` |
| LAN | `192.168.1.0/24` on bridge `br-lan` |
| Uplink side of the router | `eth1` |

Commands marked **router** run in an SSH session on the router as root. Commands marked **collector** run on the
collector.

---

## 1. Router packages

**router**

```sh
opkg update
opkg install netifyd conntrack tcpdump-mini ethtool iwinfo ip-bridge
# Optional: CAKE shaping (the "cake" subcommand and the bufferbloat pages)
opkg install sqm-scripts
# Optional: the VPN switch with a plain OpenWrt WireGuard interface
opkg install wireguard-tools
```

On OpenWrt 23.05 the firewall is fw4 (nftables). The optional firewall includes and `netmon-vpn-dns.sh` use
`iptables` commands; on fw4 they also need:

```sh
opkg install iptables-nft iptables-mod-ipopt iptables-mod-conntrack-extra kmod-nft-bridge
```

BusyBox on OpenWrt provides `flock`, `timeout`, `nc`, `sha256sum` and `awk`. Check with
`busybox --list | grep -E '^(flock|timeout|nc)$'`. If one is missing, install the package of the same name
(`coreutils-timeout`, `netcat`, `flock`).

## 2. netifyd's feed

The gate's `feed` subcommand reads netifyd's JSON stream from a local TCP socket. Make netifyd listen on
`127.0.0.1` and note the port. For netifyd 4.x, the `[socket]` section of `/etc/netifyd.conf` holds it:

```ini
[socket]
listen_address[0] = 127.0.0.1
listen_port[0] = 7150
```

**router**

```sh
/etc/init.d/netifyd restart
nc 127.0.0.1 7150 </dev/null | head -c 300; echo
```

You should see JSON. Netifyd 5 moved this output into a sink plugin: follow its documentation for a TCP
socket sink, then use that port. `FEED_PORT` in gate.conf (step 5) must match.

## 3. dnsmasq's query log

The `dnslog` subcommand follows dnsmasq's query log. Turn the log on and point it at a file in RAM.

**router**

```sh
uci set dhcp.@dnsmasq[0].logqueries='1'
uci set dhcp.@dnsmasq[0].logfacility='/tmp/dnsmasq.log'
uci commit dhcp
/etc/init.d/dnsmasq restart
nslookup example.com 127.0.0.1 >/dev/null; tail -3 /tmp/dnsmasq.log
```

The log grows with every lookup, and `/tmp` is RAM. The crontab in step 7 keeps it under 4 MB.

If dnsmasq answers some names with `0.0.0.0` or `NXDOMAIN` from a block list (`address=/name/` lines or an extra
hosts file), those lookups come through as `"status": "blocked"`. Set `dns.filter_name` in config.json to the
name the pages should show for it.

## 4. The SSH key

**collector** (as the user that runs netmon; with the systemd unit that is `netmon`, home `/var/lib/netmon`)

```sh
sudo -u netmon mkdir -p /var/lib/netmon/.ssh
sudo -u netmon ssh-keygen -t ed25519 -N '' -C netmon -f /var/lib/netmon/.ssh/id_ed25519_netmon
cat /var/lib/netmon/.ssh/id_ed25519_netmon.pub
```

On a Mac, run the same commands as your own user with the key in `~/.ssh/id_ed25519_netmon`.

**router**: append one line to `/etc/dropbear/authorized_keys`. Paste the public key where the example shows
`ssh-ed25519 AAAA... netmon`. Keep your own admin key in the file: this line adds a key, it replaces nothing.

```sh
cp /etc/dropbear/authorized_keys /etc/dropbear/authorized_keys.bak 2>/dev/null
echo 'command="/usr/bin/netmon-gate",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA... netmon' >> /etc/dropbear/authorized_keys
chmod 600 /etc/dropbear/authorized_keys
```

The `command=` option makes Dropbear run `netmon-gate` for this key, whatever the client asks for. The client's
request reaches the gate in `SSH_ORIGINAL_COMMAND`.

## 5. The gate and gate.conf

**collector** (from the repository folder). OpenWrt has no SFTP server by default, so the files go over `cat`.
Use your admin key here, not the netmon key.

```sh
R=root@192.168.1.1
ssh $R 'mkdir -p /etc/netmon'
ssh $R 'cat > /usr/bin/netmon-gate'          < router/netmon-gate
ssh $R 'cat > /usr/bin/netmon-vpn-dns.sh'    < router/netmon-vpn-dns.sh
ssh $R 'cat > /usr/bin/netmon-watchdog.sh'   < router/netmon-watchdog.sh
ssh $R 'cat > /etc/netmon/gate.conf'         < router/gate.conf.example
for f in firewall.netmon_vpn_dns firewall.netmon_prio firewall.netmon_l2block; do
  ssh $R "cat > /etc/netmon/$f" < router/$f
done
ssh $R 'chmod 755 /usr/bin/netmon-gate /usr/bin/netmon-*.sh /etc/netmon/firewall.netmon_*; chmod 600 /etc/netmon/gate.conf'
```

**router**: edit `/etc/netmon/gate.conf`. At minimum set:

- `ALLOW_FROM` to the collector's address (`192.168.1.20`). The gate refuses every other source, and refuses
  everything while this is empty.
- `WAN_IFACE`, `LAN_BRIDGES` and `WIRED_PORTS` to this router's interface names (`ip -br link` lists them).
- `FEED_PORT` to netifyd's port from step 2.
- `SHAPER_DEVS` to your CAKE devices if you use SQM (`tc qdisc | grep cake`), or empty.
- `VPN_BACKEND`: `none`, `uci` (a WireGuard interface named `VPN_IFACE`) or `glinet` (GL.iNet firmware).

Every setting is explained in the file.

**collector**: test the gate with the netmon key.

```sh
K=/var/lib/netmon/.ssh/id_ed25519_netmon
sudo -u netmon ssh -i $K -o IdentitiesOnly=yes root@192.168.1.1 vitals     # one JSON line
sudo -u netmon ssh -i $K -o IdentitiesOnly=yes root@192.168.1.1 'cat /etc/passwd'   # {"gate":"not-allowed"}
sudo -u netmon ssh -i $K -o IdentitiesOnly=yes root@192.168.1.1 dnslog      # a JSON line per lookup; Ctrl-C to stop
```

The first connection asks you to accept the router's host key. Accept it here: the collector runs with
`StrictHostKeyChecking=yes` and never accepts a new key by itself.

## 6. Optional router parts

**Firewall includes.** Each include runs on every firewall start and reload. Install only the ones you use.

- `firewall.netmon_vpn_dns`: keeps the VPN-aware DNS redirect in step with the VPN switch
  (needs `VPN_DNS_FROM_PORT` and `VPN_DNS_TO_PORT` in gate.conf).
- `firewall.netmon_prio`: puts the devices in `PRIO_MACS` into CAKE's Video tin.
- `firewall.netmon_l2block`: drops all traffic from and to the MAC addresses in `L2BLOCK_MACS`.

**router**, OpenWrt 23.05 (fw4):

```sh
for f in netmon_vpn_dns netmon_prio netmon_l2block; do
  uci set firewall.$f=include
  uci set firewall.$f.type='script'
  uci set firewall.$f.path="/etc/netmon/firewall.$f"
  uci set firewall.$f.fw4_compatible='1'
done
uci commit firewall
/etc/init.d/firewall restart
```

On GL.iNet firmware and OpenWrt 21.02 (fw3), use the same lines with `reload='1'` in place of `fw4_compatible`.

**Link watchdog.** Set `WATCHDOG_PORTS` in gate.conf to the ports that sometimes lose their link and need a replug.

## 7. Keep the files across firmware upgrades, and add the cron jobs

**router**

```sh
cat >> /etc/sysupgrade.conf <<'EOF'
/usr/bin/netmon-gate
/usr/bin/netmon-vpn-dns.sh
/usr/bin/netmon-watchdog.sh
/etc/netmon/
/etc/dropbear/authorized_keys
EOF
cat >> /etc/crontabs/root <<'EOF'
* * * * * /usr/bin/netmon-watchdog.sh >/dev/null 2>&1
*/5 * * * * f=/tmp/dnsmasq.log; [ -f $f ] && [ $(wc -c < $f) -gt 4000000 ] && rm -f $f && killall -USR2 dnsmasq
EOF
/etc/init.d/cron restart
sysupgrade -l | grep netmon
```

The same lines are in `router/sysupgrade.list` and `router/crontab.example`.

## 8. The collector

Python 3.9 or later. The standard library is enough; `pip install cryptography` adds server names read from
QUIC handshakes.

**collector**, Linux:

```sh
sudo useradd --system --home /var/lib/netmon --shell /usr/sbin/nologin netmon
sudo install -d -o netmon -g netmon /var/lib/netmon
sudo git clone <repository URL> /opt/netmon
cd /opt/netmon
sudo cp config.example.json config.json
sudo chown root:netmon config.json && sudo chmod 640 config.json
```

Edit `config.json`. The fields that matter first:

- `router.ip`, `router.ssh` (`root@192.168.1.1`), `router.key` (`/var/lib/netmon/.ssh/id_ed25519_netmon`),
  `router.wan_iface` and `router.lan_bridges`: the same names as in gate.conf.
- `collector.allow`: the addresses that may open the web interface. Keep it to your LAN.
- `zones`: one entry per LAN bridge, with its address range.
- `dns.log`: the same path as `DNS_LOG` in gate.conf.
- `latency_targets`: names and addresses to ping.
- `selftest.queue_dir`: `/var/lib/netmon/selftest/queue`, so the Run now button and the self-test agree.

```sh
python3 netmon.py --check-config config.json && echo valid
sudo cp netmon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netmon
journalctl -u netmon -n 30
```

**collector**, Mac: put the repository in `/opt/netmon` (or change the paths in `com.netmon.plist`), create the
data folder, then load the agent.

```sh
sudo mkdir -p /var/lib/netmon && sudo chown "$USER" /var/lib/netmon
cp config.example.json config.json            # then edit it as above, with router.key in your own ~/.ssh
python3 netmon.py --check-config config.json && echo valid
cp com.netmon.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.netmon.plist
```

## 9. First run

Open `http://192.168.1.20:7780/` from a machine on the allow list. Within a minute the Now page shows the
router's vitals, devices from the DHCP leases and live traffic from netifyd. DNS lookups appear as soon as a
device resolves a name. A page whose data source is not set up shows an empty state, not an error.

If nothing arrives, check in this order:

1. `journalctl -u netmon -n 50` (Linux) or `/tmp/netmon-launchd.log` (Mac) for SSH errors.
2. The gate test in step 5.
3. `logread -e netmon-gate` on the router: a `refused a request from` line means `ALLOW_FROM` does not match.

## 10. The self-test

The self-test checks the collector, the router and the pages every 15 minutes and shows the result on the
Self-test page. It reads the same config.json.

**collector**

```sh
cd /opt/netmon
sudo -u netmon env NETMON_CONFIG=/opt/netmon/config.json python3 selftest/selftest.py quick   # code, endpoints, locks
sudo -u netmon env NETMON_CONFIG=/opt/netmon/config.json python3 selftest/selftest.py bless   # record the router's files as correct
sudo -u netmon env NETMON_CONFIG=/opt/netmon/config.json python3 selftest/selftest.py run     # every layer
```

Run `bless` again after every deliberate change to the router's netmon files or SQM settings.

Schedule it on Linux:

```sh
sudo install -d -o netmon -g netmon /var/lib/netmon/selftest/queue
sudo cp selftest/netmon-selftest.service selftest/netmon-selftest.timer selftest/netmon-selftest.path /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netmon-selftest.timer netmon-selftest.path
```

On a Mac, edit the paths in `selftest/com.netmon.selftest.plist`, then:

```sh
mkdir -p /var/lib/netmon/selftest/queue
cp selftest/com.netmon.selftest.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.netmon.selftest.plist
```

The browser check of every page runs on a Mac only (it builds `selftest/webcheck.swift` with the Xcode command
line tools). On Linux that layer shows as skipped.

`selftest/canary.py` tests the self-test itself: it serves the collector through a proxy with planted faults and
reports which ones were caught.

## 11. Health reports from other machines (optional)

The Machine health page shows the collector and the router by default. Other Linux machines and Macs can push a
report every 5 minutes with `health/netmon-health.sh --push`.

1. Make a token: `python3 -c 'import secrets; print(secrets.token_urlsafe(24))'`.
2. Add the machine to `health_machines` in config.json with `"via": "push"`, its addresses in `ips` and the
   token's SHA-256 in `token_sha256` (`printf %s TOKEN | shasum -a 256`). Restart netmon.
3. On that machine:

```sh
sudo install -d /etc/netmon /opt/netmon-health
sudo cp netmon-health.sh /opt/netmon-health/
sudo sh -c 'umask 077; cat > /etc/netmon/health.conf' <<'EOF'
URL="http://192.168.1.20:7780/api/health/report"
MACHINE="nas-01"
TOKEN="paste-the-token-here"
EOF
sudo /opt/netmon-health/netmon-health.sh --push && echo sent
( sudo crontab -l 2>/dev/null; echo '*/5 * * * * /opt/netmon-health/netmon-health.sh --push >/dev/null 2>&1' ) | sudo crontab -
```

The report address skips `collector.allow`. The collector accepts a report only from the addresses listed in that
machine's `ips`, and only with its token. A Mac can also use the one-time installer the Machine health page offers.
