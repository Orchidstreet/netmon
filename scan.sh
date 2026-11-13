#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# scan.sh: checks the tree for personal data before a commit or a push.
#
# Usage:  ./scan.sh            prints every hit as "rule  file:line: text" and exits 1; silent with exit 0 when clean.
#
# Two kinds of rule:
#   1. Built-in patterns, always on: email addresses (other than the reserved example.com, example.org and
#      example.net), home-folder paths and private key blocks.
#   2. A private deny list: words and fragments that identify one operator's own network (their name, their
#      machines, their addresses). The list never ships with the repository, because publishing it would
#      publish the very data it protects. The script reads it from $NETMON_DENY if set, else ./scan.deny
#      (git-ignored), else ~/.config/netmon/scan.deny. One entry per line; blank lines and lines starting with
#      "#" are skipped. An entry made only of letters, digits, "_" or "-" matches as a whole word, ignoring
#      case. Any other entry matches as a plain substring, ignoring case. An entry that starts with "=" is
#      matched with exact case (for example "=ABC1" for a machine name that must not match "abc1").
#
# Files scanned: inside a git work tree, every tracked or untracked file that is not git-ignored; elsewhere,
# every file under this folder except .git/ and the names in .gitignore that never belong in the repository.

set -u
cd "$(dirname "$0")" || exit 2

list=$(mktemp "${TMPDIR:-/tmp}/netmon-scan.XXXXXX") || exit 2
hits=$(mktemp "${TMPDIR:-/tmp}/netmon-scan.XXXXXX") || exit 2
trap 'rm -f "$list" "$hits"' EXIT INT TERM

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git ls-files -z --cached --others --exclude-standard > "$list"
else
  find . -type f \
    ! -path './.git/*' ! -path '*/__pycache__/*' ! -path './data/*' \
    ! -name config.json ! -name '*.db' ! -name .DS_Store ! -name gate.conf ! -name health.conf \
    ! -name tokens ! -name scan.deny ! -name CONTRACT.md -print0 > "$list"
fi

# run_rule LABEL GREP-OPTIONS PATTERN: append "LABEL  file:line: text" for each match
run_rule() {
  label=$1; opts=$2; pat=$3
  # shellcheck disable=SC2086
  xargs -0 grep -nIH $opts -e "$pat" -- < "$list" 2>/dev/null \
    | cut -c1-220 | awk -v l="$label" '{ print l "  " $0 }' >> "$hits"
}

# 1. built-in patterns
run_rule "email"       "-E"  '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}'
run_rule "home-path"   "-E"  '/Users/[A-Za-z]|/home/[a-z][a-z0-9_-]*/|[A-Za-z]:\\Users\\'
run_rule "private-key" "-E"  '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----'

# reserved example domains are not personal data
if [ -s "$hits" ]; then
  grep -v -E '^email  .*@example\.(com|org|net)' "$hits" > "$hits.k" || true
  # keep a line if it still has a non-example address in it
  grep -E '^email  ' "$hits" | grep -E '@example\.(com|org|net)' | while IFS= read -r line; do
    rest=$(printf '%s\n' "$line" | sed -E 's/[A-Za-z0-9._%+-]+@example\.(com|org|net)//g')
    printf '%s\n' "$rest" | grep -qE '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}' && printf '%s\n' "$line"
  done >> "$hits.k"
  mv "$hits.k" "$hits"
fi

# 2. private deny list
deny=""
for f in "${NETMON_DENY:-}" ./scan.deny "$HOME/.config/netmon/scan.deny"; do
  if [ -n "$f" ] && [ -f "$f" ]; then deny=$f; break; fi
done
if [ -n "$deny" ]; then
  while IFS= read -r entry || [ -n "$entry" ]; do
    case $entry in ''|'#'*) continue ;; esac
    case $entry in
      =*) run_rule "deny[${entry#=}]" "-F" "${entry#=}" ;;
      *[!A-Za-z0-9_-]*) run_rule "deny[$entry]" "-F -i" "$entry" ;;
      *) run_rule "deny[$entry]" "-F -i -w" "$entry" ;;
    esac
  done < "$deny"
fi

if [ -s "$hits" ]; then
  sort -u "$hits"
  exit 1
fi
exit 0
