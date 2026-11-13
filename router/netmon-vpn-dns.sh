#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# netmon-vpn-dns.sh: keeps the LAN's DNS path in step with the VPN switch.
# While the VPN is on, LAN queries for VPN_DNS_FROM_PORT on the router are redirected to VPN_DNS_TO_PORT, a
# resolver whose own queries go through the tunnel. While the VPN is off, the redirect is removed.
# With a VPN kill switch, DNS then fails closed when the tunnel drops.
#
#   netmon-vpn-dns.sh apply | remove | sync | status
#     apply   load the redirect          remove  take it away
#     sync    apply or remove, following the VPN switch
#     status  one JSON line: {"want":"tunnel|direct","have":"tunnel|direct|partial","vpn_resolver":bool,"ok":bool}
#
# Called by netmon-gate on "vpn on" and "vpn off", and by firewall.netmon_vpn_dns on every firewall reload.
# Settings come from /etc/netmon/gate.conf. Uses iptables (fw3, or iptables-nft on fw4).

CONF=${NETMON_GATE_CONF:-/etc/netmon/gate.conf}
[ -r "$CONF" ] && . "$CONF"
: "${LAN_BRIDGES:=br-lan}" "${VPN_BACKEND:=none}" "${VPN_IFACE:=wg0}"
: "${VPN_DNS_IFACES:=$LAN_BRIDGES}"
CH=netmon_vpn_dns
FROM=$VPN_DNS_FROM_PORT
TO=$VPN_DNS_TO_PORT

if [ -z "$FROM" ] || [ -z "$TO" ] || [ "$VPN_BACKEND" = none ]; then
  # Not configured: there is never a redirect, and that state is correct.
  [ "${1:-status}" = status ] && echo '{"want":"direct","have":"direct","vpn_resolver":false,"ok":true}'
  exit 0
fi

RULE="--dport $FROM -j REDIRECT --to-ports $TO"
nifaces=0; for i in $VPN_DNS_IFACES; do nifaces=$((nifaces + 2)); done   # one UDP and one TCP rule per interface

hooked() { iptables -w -t nat -C PREROUTING -j $CH 2>/dev/null; }
nrules() { iptables -w -t nat -S $CH 2>/dev/null | grep -c -- "$RULE"; }
chain() { iptables -w -t nat -S $CH >/dev/null 2>&1; }
udp_up() { netstat -lnu 2>/dev/null | grep -q ":$TO[[:space:]]"; }
tcp_up() { netstat -lnt 2>/dev/null | grep -q ":$TO[[:space:]]"; }
flush_ct() { for p in udp tcp; do conntrack -D -p $p --orig-port-dst "$FROM" >/dev/null 2>&1; done; }
intent() {
  case "$VPN_BACKEND" in
    glinet) [ "$(uci -q get route_policy.global.enabled)" = 1 ] && [ "$(uci -q get route_policy.@rule[0].enabled)" = 1 ] ;;
    uci) [ "$(uci -q get network."$VPN_IFACE".disabled)" != 1 ] ;;
    *) return 1 ;;
  esac
}

state() {   # sets want, have, res, ok
  intent && want=tunnel || want=direct
  n=$(nrules)
  if hooked && [ "$n" -eq "$nifaces" ]; then have=tunnel
  elif hooked || chain; then have=partial
  else have=direct; fi
  udp_up && tcp_up && res=true || res=false
  ok=false
  [ "$want" = direct ] && [ "$have" = direct ] && ok=true
  [ "$want" = tunnel ] && [ "$have" = tunnel ] && [ "$res" = true ] && ok=true
}
status() { state; echo "{\"want\":\"$want\",\"have\":\"$have\",\"vpn_resolver\":$res,\"ok\":$ok}"; }

apply() {
  if ! { udp_up && tcp_up; } && [ -n "$VPN_DNS_SERVICE" ]; then "$VPN_DNS_SERVICE" start >/dev/null 2>&1; sleep 2; fi
  { echo "*nat"; echo ":$CH - [0:0]"
    for i in $VPN_DNS_IFACES; do for p in udp tcp; do echo "-A $CH -i $i -p $p -m $p $RULE"; done; done
    echo "COMMIT"; } | iptables-restore -w -n || return 1
  hooked || iptables -w -t nat -I PREROUTING 1 -j $CH || return 1
  flush_ct
}
remove() {
  chain || hooked || return 0
  while iptables -w -t nat -D PREROUTING -j $CH 2>/dev/null; do :; done
  iptables -w -t nat -F $CH 2>/dev/null; iptables -w -t nat -X $CH 2>/dev/null
  flush_ct
}

act=${1:-status}
case "$act" in
  status) status; exit 0 ;;
  apply|remove|sync) ;;
  *) echo "usage: $0 apply|remove|sync|status"; exit 2 ;;
esac
exec 8>/tmp/netmon-vpn-dns.lock
flock 8 || { logger -t netmon-vpn "VPN DNS: could not get the lock"; exit 1; }   # waits: runs are short
[ "$act" = sync ] && { intent && act=apply || act=remove; }
$act
state
if [ "$act" = apply ] && [ "$have" = tunnel ] && [ "$res" = true ]; then
  logger -t netmon-vpn "VPN DNS: port $FROM redirected to $TO (through the tunnel)"
elif [ "$act" = remove ] && [ "$have" = direct ]; then
  logger -t netmon-vpn "VPN DNS: redirect removed, port $FROM direct"
else
  logger -t netmon-vpn "VPN DNS: $act did not complete (want $want, have $have, resolver $res)"; exit 1
fi
[ "$ok" = true ] || { logger -t netmon-vpn "VPN DNS: state does not match the switch (want $want, have $have)"; exit 1; }
