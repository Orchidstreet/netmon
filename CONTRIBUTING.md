# Contributing

Thank you for helping. Four rules:

1. **Comments say what the code does.** Present tense. No dates, no names, no history of what it used to do or
   why it changed. That belongs in the commit message.
2. **No personal data.** No names, addresses, emails, hostnames, MAC addresses, tokens, keys or home-folder
   paths from any real network. Examples use RFC 5737 addresses (192.0.2.0/24, 198.51.100.0/24,
   203.0.113.0/24), private ranges that are clearly invented, and invented hostnames.
3. **Run `./scan.sh` before every commit.** It must print nothing. Keep your own network's words in a private
   `scan.deny` file (git-ignored) so the scan catches them too; `scan.sh` explains the format.
4. **AGPL-3.0.** Contributions are accepted under the GNU Affero General Public License, version 3 or later.
   Every source file starts with `SPDX-License-Identifier: AGPL-3.0-or-later` in its comment style.

Before a pull request, also run the checks in `CLAUDE.md`: the Python compile check, `node --check` on every
web script, and `python3 netmon.py --check-config config.example.json`.
