#!/usr/bin/env python
"""Directory scan deduplicated across sessions (called by Claude Code workers instead of running dirsearch directly).

When several sessions call it for the same URL, only one actually runs dirsearch; the others block and reuse its report,
avoiding repeated scans of the same target, wasted time, and tripping the target's rate limiting.

Usage:
    python tools/dirsearch_scan.py <url>

Behaves the same as cruiser.tools.dirsearch_scan:
- results are cached in /tmp/cruiser_dirsearch_cache keyed by the sha256 of the normalized URL;
- the first caller holds the lock and runs it once (built-in -i 200,301,302 --format=plain); other sessions wait for the cached result (up to 5 minutes);
- the plain-text report is printed to stdout.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cruiser.tools import dirsearch_scan as _dirsearch_scan_tool


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python tools/dirsearch_scan.py <url>")
        return 2
    url = sys.argv[1]
    out = _dirsearch_scan_tool.invoke({"url": url})
    print(out if isinstance(out, str) else str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
