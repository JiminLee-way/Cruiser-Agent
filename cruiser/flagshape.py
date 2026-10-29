from __future__ import annotations

import re

FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[A-Za-z0-9_+\-./:=]{8,300}\}")
PLACEHOLDER = "<flag>"


def redact(text: str) -> str:
    return FLAG_RE.sub(PLACEHOLDER, text or "")
