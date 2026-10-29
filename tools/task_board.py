#!/usr/bin/env python
"""Command line for the exploration-direction task board (called by Claude Code workers).

Usage:
    python tools/task_board.py list <code>                        # list directions waiting to be claimed
    python tools/task_board.py claim <code> <worker_id> [task_id] # claim (claiming erases it; without an id, claims the first one)
    python tools/task_board.py report <code> <worker_id> <result> [--basis f-a,r-b]
                                                    # report the outcome (written to the shared blackboard),
                                                    # optionally naming the blackboard entry ids it rests on

On a successful claim, prints the direction and exits with code 0; exits with code 3 when there is nothing to claim.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cruiser.taskboard import claim_task, list_tasks, report_task


def _pop_basis(args: list[str]) -> list[str]:
    if "--basis" not in args:
        return []
    i = args.index("--basis")
    value = args[i + 1] if i + 1 < len(args) else ""
    del args[i: i + 2]
    return [b.strip() for b in value.split(",") if b.strip()]


def main() -> int:
    basis = _pop_basis(sys.argv)
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    action, code = sys.argv[1], sys.argv[2]

    if action == "list":
        tasks = list_tasks(code)
        if not tasks:
            print("(no exploration directions waiting to be claimed)")
            return 0
        for t in tasks:
            print(f"{t['id']}: {t['text']}")
        return 0

    if action == "claim":
        if len(sys.argv) < 4:
            print("Usage: python tools/task_board.py claim <code> <worker_id> [task_id]")
            return 2
        worker_id = sys.argv[3]
        task_id = sys.argv[4] if len(sys.argv) > 4 else None
        # tolerate mistakes: the worker may have put task_id where worker_id goes (claim <code> t-xxxxxx)
        import re as _re
        if _re.fullmatch(r"t-[0-9a-f]{6}", worker_id or "") and task_id is None:
            task_id = worker_id
            worker_id = os.environ.get("CRUISER_WORKER_ID", "unknown")
        claimed = claim_task(code, worker_id, task_id)
        if claimed is None:
            print("no direction available to claim (or it was already claimed by another session)")
            return 3
        print(f"claimed {claimed['id']}: {claimed['text']}")
        print("when done, run: python tools/task_board.py report <code> <worker_id> '<outcome>'")
        return 0

    if action == "report":
        if len(sys.argv) < 5:
            print("Usage: python tools/task_board.py report <code> <worker_id> <outcome> [--basis f-a,r-b]")
            return 2
        worker_id = sys.argv[3]
        text = sys.argv[4]
        if report_task(code, worker_id, text, basis=basis):
            print("reported; the result has been shared to the blackboard")
            return 0
        return 1

    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
