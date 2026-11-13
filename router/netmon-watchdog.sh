#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# netmon-watchdog.sh: a software replug for wired ports that lose carrier and stay down.
# Runs from cron every minute. For each port in WATCHDOG_PORTS it acts only when the port has had no carrier
# for WATCHDOG_DOWN_AFTER seconds, so it never touches a working link. It first renegotiates (ethtool -r),
# then, if the port is still down, sets the link down and up. At most one reset per port every
# WATCHDOG_MIN_GAP seconds. Settings come from /etc/netmon/gate.conf. Log: logread -e netmon-watchdog
CONF=${NETMON_GATE_CONF:-/etc/netmon/gate.conf}
[ -r "$CONF" ] && . "$CONF"
: "${WATCHDOG_DOWN_AFTER:=60}" "${WATCHDOG_MIN_GAP:=300}"
[ -n "$WATCHDOG_PORTS" ] || exit 0
now=$(date +%s); echo "$now" > /tmp/netmon-watchdog.heartbeat
carrier() { cat /sys/class/net/$1/carrier 2>/dev/null || echo 0; }
say() { logger -t netmon-watchdog "$*"; }

for PORT in $WATCHDOG_PORTS; do
  [ -d /sys/class/net/$PORT ] || continue
  STATE=/tmp/netmon-watchdog.$PORT.down      # time the carrier was first seen down
  LAST=/tmp/netmon-watchdog.$PORT.reset      # time of the last reset
  if [ "$(carrier $PORT)" = 1 ]; then
    [ -f "$STATE" ] && { say "$PORT carrier back after $((now - $(cat $STATE)))s"; rm -f "$STATE"; }
    continue
  fi
  [ -f "$STATE" ] || { echo "$now" > "$STATE"; say "$PORT carrier lost"; continue; }
  down_for=$((now - $(cat $STATE)))
  [ "$down_for" -lt "$WATCHDOG_DOWN_AFTER" ] && continue
  [ -f "$LAST" ] && [ $((now - $(cat $LAST))) -lt "$WATCHDOG_MIN_GAP" ] && continue
  echo "$now" > "$LAST"
  say "$PORT down ${down_for}s: renegotiating (ethtool -r)"
  ethtool -r "$PORT" 2>/dev/null
  sleep 10
  if [ "$(carrier $PORT)" != 1 ]; then
    say "$PORT still down: setting the link down and up"
    ip link set "$PORT" down; sleep 3; ip link set "$PORT" up
    sleep 10
  fi
  say "$PORT after reset: carrier=$(carrier $PORT) speed=$(cat /sys/class/net/$PORT/speed 2>/dev/null)"
done
