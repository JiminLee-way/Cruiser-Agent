"""Cruiser package init.

Globally disable LangSmith/LangChain tracing to avoid outbound requests and quota issues.
Runs before any submodule is imported, so subprocesses inherit the disabled state by default.

"""

from __future__ import annotations

import os


# Force tracing off (overrides external environment settings)
os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"

# Also remove any API keys that may be present, to avoid accidentally triggering SDK initialization
for _k in ("LANGSMITH_API_KEY", "LANGCHAIN_API_KEY"):
    os.environ.pop(_k, None)


def _load_dotenv() -> None:
    """Load the project-root .env (if present); never overrides existing environment variables.

    Supplies LLM keys such as DEEPSEEK_API_KEY and CRUISER_* settings,
    so main.py and the subprocesses it spawns all get the credentials.
    """
    try:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env_path = os.path.join(root, ".env")
        if not os.path.exists(env_path):
            return
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception:
        pass


_load_dotenv()




__all__ = [
    "tools",
]
