#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Entry point: `python3 netmon.py [--config FILE]` runs netmon; `--check-config FILE` validates a config."""
import sys

from netmon.main import main

if __name__ == "__main__":
    sys.exit(main())
