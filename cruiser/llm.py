from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Optional, Tuple

# ---------------------------------------------------------------------------
# LLM provider configuration (single source of truth, table-driven)
#
# Principles:
#   1. All keys are read from environment variables (configurable in the project-root .env); the source contains no hard-coded keys.
#   2. The provider is determined by a "model name prefix" mapping, see MODEL_PREFIX_TO_PROVIDER.
#   3. Each provider's endpoints/key environment variables are registered centrally in the PROVIDERS registry;
#      to add a provider: add one entry to PROVIDERS + add its prefix to MODEL_PREFIX_TO_PROVIDER; callers need no changes.
#
# Currently registered:
#   - deepseek: default for the solving engine (claude CLI) and the watcher;
#   - kimi (moonshot): routed automatically when the worker/watcher specifies a kimi-* model;
#   - glm (Tencent TokenHub): routed automatically when the worker/watcher specifies a glm-* model.
#   Endpoints default to each vendor's official https address and can be overridden with the matching *_BASE_URL environment variable.
# ---------------------------------------------------------------------------

# Default models (each can be overridden with an environment variable)
DEFAULT_SOLVE_MODEL = "deepseek-v4-flash"     # default model for the solving engine
DEFAULT_WATCHER_MODEL = "deepseek-v4-pro"     # default model for the blackboard watcher (curation needs stronger reasoning)


@dataclass(frozen=True)
class ProviderConfig:
    """Connection settings for one LLM provider. Endpoint defaults can be overridden with the matching environment variables."""
    name: str
    api_key_env: str              # name of the key environment variable
    anthropic_base_url: str       # default Anthropic-compatible endpoint (used by the claude CLI)
    openai_base_url: str          # default OpenAI-compatible endpoint (used by the langchain watcher)
    anthropic_base_url_env: str   # environment variable that overrides the Anthropic endpoint
    openai_base_url_env: str      # environment variable that overrides the OpenAI endpoint
    max_context_tokens: int = 1_000_000    # the model's real context window (lets the claude CLI calibrate auto-compact)
    auto_compact_window: int = 800_000     # threshold for triggering context compaction early


def _resolve_anthropic_base_url(cfg: "ProviderConfig") -> str:
    """Resolve the Anthropic endpoint: explicit environment override > default official endpoint."""
    return os.environ.get(cfg.anthropic_base_url_env) or cfg.anthropic_base_url


def _resolve_openai_base_url(cfg: "ProviderConfig") -> str:
    """Resolve the OpenAI-compatible endpoint: explicit environment override > default official endpoint."""
    return os.environ.get(cfg.openai_base_url_env) or cfg.openai_base_url


# Provider registry: provider name -> config
PROVIDERS: dict[str, ProviderConfig] = {
    "deepseek": ProviderConfig(
        name="deepseek",
        api_key_env="DEEPSEEK_API_KEY",
        anthropic_base_url="https://api.deepseek.com/anthropic",
        openai_base_url="https://api.deepseek.com/v1",
        anthropic_base_url_env="ANTHROPIC_BASE_URL",
        openai_base_url_env="DEEPSEEK_BASE_URL",
    ),
    # Kimi / Moonshot (China domain; the international site is api.moonshot.ai, override with the *_env settings below)
    "kimi": ProviderConfig(
        name="kimi",
        api_key_env="KIMI_API_KEY",
        anthropic_base_url="https://api.moonshot.cn/anthropic",
        openai_base_url="https://api.moonshot.cn/v1",
        anthropic_base_url_env="KIMI_ANTHROPIC_BASE_URL",
        openai_base_url_env="KIMI_BASE_URL",
    ),
    # GLM (Zhipu) via the Tencent TokenHub aggregation gateway: compatible with both the Anthropic Messages and OpenAI Chat protocols.
    # The Anthropic protocol auth header is x-api-key (sent the same way as ANTHROPIC_AUTH_TOKEN);
    # the OpenAI protocol uses Authorization: Bearer (the langchain ChatOpenAI default). The same key works for both.
    "glm": ProviderConfig(
        name="glm",
        api_key_env="GLM_API_KEY",
        anthropic_base_url="https://tokenhub.tencentmaas.com",
        openai_base_url="https://tokenhub.tencentmaas.com/v1",
        anthropic_base_url_env="GLM_ANTHROPIC_BASE_URL",
        openai_base_url_env="GLM_BASE_URL",
        # TokenHub docs: glm-5.3 / glm-5.2 have a 1M context and 128K max output, the same as DeepSeek.
        # Note glm-5.1 / glm-5 / glm-5-turbo only have 200K: when using these older models, explicitly set
        # CLAUDE_CODE_MAX_CONTEXT_TOKENS=200000 (and lower AUTO_COMPACT_WINDOW accordingly).
        max_context_tokens=1_000_000,
        auto_compact_window=800_000,
    ),
}

# Model name prefix -> provider (lowercase match). A hit routes to that provider; otherwise DEFAULT_PROVIDER is used.
MODEL_PREFIX_TO_PROVIDER: dict[str, str] = {
    "deepseek": "deepseek",
    "kimi": "kimi",
    "moonshot": "kimi",
    "glm": "glm",
    "chatglm": "glm",
    "zhipu": "glm",
}
DEFAULT_PROVIDER = "deepseek"

_GLM_MODEL_RE = re.compile(r"^glm-?(\d.*)$", re.IGNORECASE)


def _normalize_glm_model(model: str) -> str:
    """Normalize glm model names: TokenHub model IDs look like glm-5.3; glm5.3 / GLM5.3 spellings are tolerated."""
    m = _GLM_MODEL_RE.match((model or "").strip())
    return f"glm-{m.group(1)}" if m else model


# ---------------------------------------------------------------------------
# Provider resolution
# ---------------------------------------------------------------------------
def provider_for_model(model: str) -> str:
    """Determine the provider from the model name: use the mapping of any matching prefix in MODEL_PREFIX_TO_PROVIDER, otherwise the default."""
    m = (model or "").lower()
    for prefix, provider in MODEL_PREFIX_TO_PROVIDER.items():
        if m.startswith(prefix) or prefix in m:
            return provider
    return DEFAULT_PROVIDER


def get_provider_config(name: str) -> ProviderConfig:
    return PROVIDERS.get(name) or PROVIDERS[DEFAULT_PROVIDER]


def _provider_api_key(cfg: ProviderConfig) -> str:
    return (os.environ.get(cfg.api_key_env) or "").strip()


def get_deepseek_api_key() -> str:
    """DeepSeek key (read only from the environment; empty string if missing)."""
    return _provider_api_key(PROVIDERS["deepseek"])


def get_kimi_api_key() -> str:
    """Kimi / Moonshot key (read only from the environment; empty string if missing)."""
    return _provider_api_key(PROVIDERS["kimi"])


def get_glm_api_key() -> str:
    """GLM (Tencent TokenHub) key (read only from the environment; empty string if missing)."""
    return _provider_api_key(PROVIDERS["glm"])


def get_solve_model() -> str:
    """Model used by the solving engine (claude CLI).

    Priority: CRUISER_MODEL > ANTHROPIC_MODEL > DEEPSEEK_MODEL > default.
    glm-family model names are normalized (glm5.3 -> glm-5.3) to match TokenHub model IDs.
    """
    model = os.environ.get("CRUISER_MODEL") or os.environ.get("ANTHROPIC_MODEL") or os.environ.get("DEEPSEEK_MODEL") or DEFAULT_SOLVE_MODEL
    if provider_for_model(model) == "glm":
        return _normalize_glm_model(model)
    return model


def get_watcher_model() -> str:
    """Model used by the blackboard watcher (overridden by WATCHER_MODEL, default deepseek-v4-pro). glm-family names are normalized."""
    model = os.environ.get("WATCHER_MODEL", DEFAULT_WATCHER_MODEL)
    if provider_for_model(model) == "glm":
        return _normalize_glm_model(model)
    return model


def get_context_defaults(model: str) -> tuple[int, int]:
    """Return the provider defaults for (max context tokens, auto-compact trigger window).

    Used by claude_agent._claude_env to setdefault CLAUDE_CODE_MAX_CONTEXT_TOKENS /
    CLAUDE_CODE_AUTO_COMPACT_WINDOW: DeepSeek has a 1M window, GLM about 200K.
    Environment variables set explicitly by the user always take precedence.
    """
    cfg = get_provider_config(provider_for_model(model))
    return cfg.max_context_tokens, cfg.auto_compact_window


# ---------------------------------------------------------------------------
# Solving engine: Anthropic-compatible endpoint config for the claude CLI
# ---------------------------------------------------------------------------
def get_claude_provider_env() -> dict[str, str]:
    """Return the environment variables the claude CLI needs to reach an Anthropic-compatible endpoint.

    Responsible only for "which model/endpoint/key to use"; claude runtime switches (sandbox, context
    compaction window, reversing environment, etc.) are handled by claude_agent._claude_env; the two are kept separate.
    The provider is routed automatically by model name; the key is that provider's key, falling back to an explicit ANTHROPIC_AUTH_TOKEN when missing.
    """
    model = get_solve_model()
    cfg = get_provider_config(provider_for_model(model))
    base_url = _resolve_anthropic_base_url(cfg)
    key = (_provider_api_key(cfg) or os.environ.get("ANTHROPIC_AUTH_TOKEN") or "").strip()
    return {
        "ANTHROPIC_BASE_URL": base_url,
        "ANTHROPIC_AUTH_TOKEN": key,
        "ANTHROPIC_MODEL": model,
        "ANTHROPIC_SMALL_FAST_MODEL": model,
    }


# ---------------------------------------------------------------------------
# langchain (watcher / legacy ReAct engine): OpenAI-compatible endpoint
# ---------------------------------------------------------------------------
def _compute_temperature() -> float:
    """Assign temperatures from low to high by session index, based on the concurrent session ID and count (langchain path only).

    - When CRUISER_SESSIONS<=1 or unset, returns CRUISER_TEMP_MIN (default 0.0).
    - Linear range [CRUISER_TEMP_MIN, CRUISER_TEMP_MAX], split evenly by worker_id over [1..sessions].
    """
    try:
        wid = int(os.environ.get("CRUISER_WORKER_ID", "1") or "1")
    except Exception:
        wid = 1
    try:
        total = int(os.environ.get("CRUISER_SESSIONS", "1") or "1")
    except Exception:
        total = 1
    try:
        tmin = float(os.environ.get("CRUISER_TEMP_MIN", "0.0") or "0.0")
    except Exception:
        tmin = 0.0
    try:
        tmax = float(os.environ.get("CRUISER_TEMP_MAX", "0.9") or "0.9")
    except Exception:
        tmax = 0.9
    if total <= 1:
        return max(0.0, min(1.0, tmin))
    wid = max(1, min(wid, total))
    step = (tmax - tmin) / max(1, total - 1)
    temp = tmin + (wid - 1) * step
    return max(0.0, min(1.0, temp))


def _build_chat_openai(model: str, temperature: Optional[float]) -> Optional[Any]:
    """Build an OpenAI-compatible langchain ChatOpenAI instance (for the watcher / legacy engine).

    The provider is routed automatically by model name (endpoint and key come from the PROVIDERS registry).
    Returns None (without raising) when there is no key, a dependency is missing, or construction fails.
    When temperature is None the parameter is not passed (the server default applies).
    """
    cfg = get_provider_config(provider_for_model(model))
    key = _provider_api_key(cfg)
    if not key:
        return None
    base_url = _resolve_openai_base_url(cfg)
    try:
        from langchain_openai import ChatOpenAI  # type: ignore
    except Exception:  # noqa: BLE001
        return None
    kwargs: dict = {"model": model, "base_url": base_url, "api_key": key}
    if temperature is not None:
        kwargs["temperature"] = temperature
    try:
        return ChatOpenAI(**kwargs)
    except Exception:  # noqa: BLE001
        return None


def get_llm() -> Tuple[Optional[Any], str, bool]:
    """langchain model for solving (legacy ReAct engine path; the main engine is now the claude CLI, so this is usually not used).

    Returns a triple (llm, provider, supports_tool_calls); returns (None, "none", False) when no key/dependency is available.
    Marked as not supporting native tool calling, so the JSON decision path is used.
    """
    model = os.environ.get("DEEPSEEK_MODEL", DEFAULT_SOLVE_MODEL)
    llm = _build_chat_openai(model, _compute_temperature())
    if llm is None:
        return None, "none", False
    return llm, provider_for_model(model), False


def get_watcher_llm() -> Tuple[Optional[Any], str, bool]:
    """Dedicated LLM for the blackboard watcher (curation/task publishing), default DeepSeek deepseek-v4-pro (overridden by WATCHER_MODEL).

    kimi-* models go to the Kimi endpoint automatically. No temperature is passed when WATCHER_TEMPERATURE is unset.
    Falls back to get_llm() when there is no key.
    """
    temp_env = os.environ.get("WATCHER_TEMPERATURE", "").strip()
    try:
        temperature: Optional[float] = float(temp_env) if temp_env else None
    except Exception:
        temperature = None
    model = get_watcher_model()
    llm = _build_chat_openai(model, temperature)
    if llm is None:
        return get_llm()
    return llm, model, False
