#!/usr/bin/env python
"""Submit a flag from the command line (called by the Claude Code engine while solving).

Usage:
    python tools/submit_flag.py <challenge_code> <flag>

The output matches the cruiser.tools.submit_flag tool and includes the local challenge platform's confirmation marker:
- "FLAG CORRECT" / "ALREADY SUBMITTED" mean the platform confirmed success
- any other output means failure or an error
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cruiser.tools import submit_flag as _submit_flag_tool


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: python tools/submit_flag.py <challenge_code> <flag>")
        return 2
    challenge_code = sys.argv[1]
    flag = sys.argv[2]
    out = _submit_flag_tool.invoke({"challenge_code": challenge_code, "flag": flag})
    print(out if isinstance(out, str) else str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
