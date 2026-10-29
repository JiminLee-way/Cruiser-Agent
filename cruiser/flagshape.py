"""The one definition of an answer-token-shaped string (PREFIX{body}).

The scheduler auto-submits every such string it sees in session output and in the rendered board, so shared
state (ledger, task board) stores them only redacted.
"""
from __future__ import annotations

import re

FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[A-Za-z0-9_+\-./:=]{8,300}\}")
PLACEHOLDER = "<flag>"


def redact(text: str) -> str:
    return FLAG_RE.sub(PLACEHOLDER, text or "")
