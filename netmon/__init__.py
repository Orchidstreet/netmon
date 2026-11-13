# SPDX-License-Identifier: AGPL-3.0-or-later
"""netmon: a network monitor for an OpenWrt router.

A collector reads the router through one restricted ssh command (netmon-gate), stores flows,
devices, DNS lookups and health readings in SQLite, runs checks, and serves a web interface.
See docs/ARCHITECTURE.md for the module map.
"""
__version__ = "1.0.0"
