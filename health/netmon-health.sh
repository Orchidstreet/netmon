#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# netmon-health.sh: read-only machine health for netmon's Machine health page, for macOS and Linux.
# It changes nothing on the machine: no installs, no update downloads, no settings. Slow checks (the update
# lists) are cached for an hour.
#
# Usage:
#   netmon-health.sh                       print the report on stdout
#   netmon-health.sh --push [options]      send the report to the collector
#     --url URL         report endpoint, for example http://192.168.1.20:7780/api/health/report
#     --machine ID      this machine's id in the collector's "health_machines" list
#     --token-file F    file holding this machine's token (preferred: a token on the command line shows in ps)
#     --token T         the token itself
#     --conf F          settings file (default: $NETMON_HEALTH_CONF, else /etc/netmon/health.conf,
#                       else ~/.config/netmon/health.conf)
# The settings file holds NAME="value" lines: URL, MACHINE, TOKEN_FILE or TOKEN. Arguments override it.
# The push sends the report as text/plain with the headers X-Health-Machine and X-Health-Token.
# Run it every 5 minutes from cron, a systemd timer or a launchd agent (see docs/INSTALL.md).
#
# Report format: one fact per line, kind|field|field...
# Kinds: v host os model uptime load cpus mem swap disk pool temp therm batt smart net addr upd updc posture
#        reboot backup
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/opt/homebrew/bin:/usr/local/bin:$PATH
export LC_ALL=C

report() {
CACHE=${NETMON_HEALTH_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/netmon-health}
mkdir -p "$CACHE" 2>/dev/null
clean() { tr -d '|\r' | tr '\n\t' '  ' | sed 's/  */ /g; s/^ //; s/ $//' | cut -c1-300; }
# cached NAME SECONDS COMMAND...: reruns COMMAND only when its cached output is older than SECONDS
cached() {
  f="$CACHE/$1"; age=$2; shift 2
  if [ -f "$f" ] && [ $(( $(date +%s) - $(stat -f %m "$f" 2>/dev/null || stat -c %Y "$f" 2>/dev/null || echo 0) )) -lt "$age" ]; then cat "$f"; return; fi
  "$@" > "$f.tmp" 2>/dev/null; mv "$f.tmp" "$f" 2>/dev/null; cat "$f" 2>/dev/null
}
echo "v|1|$(date +%s)"

if [ "$(uname -s)" = Darwin ]; then
  echo "host|$(scutil --get ComputerName 2>/dev/null | clean)|$(hostname -s | clean)"
  echo "os|macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion))|$(uname -r)"
  echo "model|$(sysctl -n hw.model | clean)|$(sysctl -n machdep.cpu.brand_string 2>/dev/null | clean)"
  echo "uptime|$(( $(date +%s) - $(sysctl -n kern.boottime | sed 's/^{ sec = \([0-9]*\),.*/\1/') ))"
  echo "load|$(sysctl -n vm.loadavg | tr -d '{}' | awk '{print $1"|"$2"|"$3}')"
  echo "cpus|$(sysctl -n hw.ncpu)"
  ps=$(sysctl -n hw.pagesize)
  vm_stat | awk -v ps="$ps" -v tot="$(sysctl -n hw.memsize)" -v pr="$(sysctl -n kern.memorystatus_vm_pressure_level 2>/dev/null)" '
    /Pages free/ {f=$3} /Pages inactive/ {i=$3} /Pages speculative/ {s=$3} /Pages purgeable/ {p=$4}
    END { printf "mem|%d|%d|%s\n", tot/1024, (f+i+s+p)*ps/1024, (pr==1?"normal":pr==2?"warning":pr==4?"critical":"unknown") }'
  sysctl -n vm.swapusage | awk '{u=$6; t=$3; sub(/M/,"",u); sub(/M/,"",t); printf "swap|%d|%d\n", t*1024, u*1024}'
  # every local disk volume except the read-only system volume and the system's helper volumes
  df -kPl 2>/dev/null | awk 'NR>1 && $1 ~ /^\/dev\/disk/ {m=$6; for(i=7;i<=NF;i++) m=m" "$i
    if (m == "/" || (m ~ /^\/System\// && m !~ /\/Data$/)) next
    printf "disk|%s|apfs|%d|%d|%d\n", m, $2, $3, $4}'
  pmset -g therm 2>/dev/null | awk -F= '/CPU_Speed_Limit/ {gsub(/ /,"",$2); print "therm|cpu_speed_limit|"$2}'
  pmset -g therm 2>/dev/null | grep -q "No thermal warning level" && echo "therm|warning|none"
  ioreg -rn AppleSmartBattery 2>/dev/null | awk -F' = ' '
    /"CycleCount" =/ {c=$2} /"Temperature" =/ {t=$2} /"AppleRawMaxCapacity" =/ {m=$2} /"DesignCapacity" =/ {d=$2} /"ExternalConnected" =/ {e=$2}
    /"CurrentCapacity" =/ {cc=$2} END { if (d) printf "batt|%d|%.0f|%.1f|%s|%s\n", c, 100*m/d, t/100, (e=="Yes"?"mains":"battery"), cc }'
  echo "smart|disk0|$(diskutil info disk0 2>/dev/null | awk -F': *' '/SMART Status/ {print $2}' | clean)"
  netstat -ibn | awk '$3 ~ /^<Link#/ && $1 ~ /^en[0-9]/ && $7 > 0 {print "net|"$1"|"$7"|"$10"|"$4}' | sort -u -t'|' -k2,2
  for i in $(ifconfig -l); do a=$(ipconfig getifaddr "$i" 2>/dev/null) && echo "addr|$i|$a"; done
  # updates: Apple's list from macOS's last background scan (no new scan) and Homebrew's local metadata
  cached su 3600 softwareupdate -l --no-scan | awk '/^\* Label:/ {sub(/^\* Label: /,""); l=$0} /Title:/ {r=($0 ~ /Action: restart/)?"restart":""; print "upd|macos|"l"|"r}'
  if command -v brew >/dev/null 2>&1; then
    n=$(cached brew 3600 env HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 brew outdated --quiet | wc -l | tr -d ' ')
    api=$(ls -t "$HOME/Library/Caches/Homebrew/api/"*.jws.json 2>/dev/null | head -1)
    echo "updc|brew|$n|$( [ -n "$api" ] && stat -f %m "$api" || echo 0)|$(head -12 "$CACHE/brew" 2>/dev/null | clean)"
  fi
  echo "posture|filevault|$(fdesetup status 2>/dev/null | head -1 | clean)"
  echo "posture|firewall|$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | clean)"
  echo "posture|sip|$(csrutil status 2>/dev/null | clean)"
  echo "posture|gatekeeper|$(spctl --status 2>/dev/null | clean)"
  echo "posture|auto_macos|$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo unset)"
  echo "posture|auto_security|$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo unset)"
  echo "posture|remote_login|$(netstat -anp tcp 2>/dev/null | awk '$4 ~ /[.:]22$/ && $6=="LISTEN"' | grep -q . && echo open || echo closed)"
  echo "posture|screen_sharing|$(netstat -anp tcp 2>/dev/null | awk '$4 ~ /[.:]5900$/ && $6=="LISTEN"' | grep -q . && echo open || echo closed)"
  echo "backup|timemachine|$(tmutil latestbackup 2>/dev/null | clean)"
else
  . /etc/os-release 2>/dev/null
  echo "host|$(hostname | clean)|$(hostname -s 2>/dev/null | clean)"
  pv=$(command -v pveversion >/dev/null 2>&1 && pveversion 2>/dev/null | clean)
  echo "os|${PRETTY_NAME:-Linux}${pv:+ · $pv}|$(uname -r)"
  echo "model|$(cat /sys/class/dmi/id/product_name 2>/dev/null | clean)|$(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo | clean)"
  echo "uptime|$(cut -d. -f1 /proc/uptime)"
  echo "load|$(awk '{print $1"|"$2"|"$3}' /proc/loadavg)"
  echo "cpus|$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)"
  awk '/^MemTotal/ {t=$2} /^MemAvailable/ {a=$2} /^SwapTotal/ {st=$2} /^SwapFree/ {sf=$2} END {print "mem|"t"|"a"|"; print "swap|"st"|"st-sf}' /proc/meminfo
  df -kPT -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs -x fuse.lxcfs -x zfs -x iso9660 -x vfat 2>/dev/null | awk 'NR>1 && $3 > 0 {print "disk|"$7"|"$2"|"$3"|"$4"|"$5}'
  command -v zpool >/dev/null 2>&1 && zpool list -Hp -o name,size,alloc,free,health 2>/dev/null | awk '{print "pool|"$1"|"$2"|"$3"|"$4"|"$5}'
  for z in /sys/class/thermal/thermal_zone*; do [ -r "$z/temp" ] && echo "temp|$(cat "$z/type" | clean)|$(awk '{printf "%.1f", $1/1000}' "$z/temp")"; done
  for h in /sys/class/hwmon/hwmon*; do n=$(cat "$h/name" 2>/dev/null); for t in "$h"/temp*_input; do [ -r "$t" ] || continue
    l=$(cat "${t%_input}_label" 2>/dev/null || echo "$n"); echo "temp|$(echo "$n $l" | clean)|$(awk '{printf "%.1f", $1/1000}' "$t")"; done; done | sort -u | head -24
  command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi --query-gpu=name,temperature.gpu --format=csv,noheader 2>/dev/null | awk -F', ' '{print "temp|GPU "$1"|"$2}'
  if [ "$(id -u)" = 0 ] && command -v smartctl >/dev/null 2>&1; then for d in $(lsblk -dno NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}'); do
    echo "smart|$d|$(smartctl -H /dev/$d 2>/dev/null | awk -F': *' '/overall-health|SMART Health Status/ {print $2}' | clean)"; done; fi
  awk -F'[: ]+' 'NR>2 && $2 !~ /^(lo|veth|fwbr|fwln|fwpr|tap|docker|br-)/ {print "net|"$2"|"$3"|"$11}' /proc/net/dev
  for i in $(ls /sys/class/net | grep -v "^lo$"); do m=$(cat /sys/class/net/$i/address 2>/dev/null); a=$(ip -4 -o addr show "$i" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1); [ -n "$a" ] && echo "addr|$i|$a|$m"; done
  if command -v apt >/dev/null 2>&1; then
    lists=$(stat -c %Y /var/cache/apt/pkgcache.bin 2>/dev/null || echo 0)
    cached apt 3600 apt list --upgradable 2>/dev/null >/dev/null
    n=$(grep -c '\[upgradable' "$CACHE/apt" 2>/dev/null); s=$(grep '\[upgradable' "$CACHE/apt" 2>/dev/null | grep -c -- '-security')
    echo "updc|apt|${n:-0}|$lists|$(grep '\[upgradable' "$CACHE/apt" 2>/dev/null | cut -d/ -f1 | head -12 | clean)|${s:-0}"
    echo "posture|unattended_upgrades|$(dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'install ok installed' && echo installed || echo missing)"
  fi
  [ -f /var/run/reboot-required ] && echo "reboot|required|$(cat /var/run/reboot-required.pkgs 2>/dev/null | head -5 | clean)"
fi
}

[ "$1" = "--push" ] || { report; exit 0; }
shift

CONF=${NETMON_HEALTH_CONF:-}
if [ -z "$CONF" ]; then
  for c in /etc/netmon/health.conf "$HOME/.config/netmon/health.conf"; do [ -r "$c" ] && { CONF=$c; break; }; done
fi
while [ $# -gt 0 ]; do
  case "$1" in
    --conf) CONF=$2; shift 2 ;;
    *) break ;;
  esac
done
URL=; MACHINE=; TOKEN=; TOKEN_FILE=
[ -n "$CONF" ] && [ -r "$CONF" ] && . "$CONF"
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL=$2; shift 2 ;;
    --machine) MACHINE=$2; shift 2 ;;
    --token) TOKEN=$2; shift 2 ;;
    --token-file) TOKEN_FILE=$2; shift 2 ;;
    --conf) shift 2 ;;
    *) echo "netmon-health: unknown option $1" >&2; exit 2 ;;
  esac
done
[ -z "$TOKEN" ] && [ -n "$TOKEN_FILE" ] && TOKEN=$(head -1 "$TOKEN_FILE" 2>/dev/null | tr -d '\r\n')
[ -n "$URL" ] && [ -n "$MACHINE" ] && [ -n "$TOKEN" ] || { echo "netmon-health: --push needs a URL, a machine id and a token" >&2; exit 2; }
case "$MACHINE$TOKEN" in *[!A-Za-z0-9._-]*) echo "netmon-health: machine id and token may use letters, digits, dot, dash and underscore only" >&2; exit 2 ;; esac

umask 077
H=$(mktemp "${TMPDIR:-/tmp}/netmon-health.XXXXXX") || exit 1
trap 'rm -f "$H"' EXIT INT TERM
printf 'X-Health-Machine: %s\nX-Health-Token: %s\nContent-Type: text/plain\n' "$MACHINE" "$TOKEN" > "$H"
report 2>/dev/null | curl -fsS -m 30 -X POST -H @"$H" --data-binary @- "$URL" >/dev/null
