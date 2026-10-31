"""LLM provider abstraction for the agent layer.

Rules:
- Never make network calls in offline mode.
- Always apply redact_secrets() before submitting any text to a provider.
- Credentials are read from environment variables only; never hardcoded.
- Provider failures must not erase existing deterministic findings.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Optional

from auditor.core.config import ScanConfig
from auditor.core.safety import redact_secrets


class BaseProvider(ABC):
    """Abstract LLM provider interface."""

    name: str = "base"
    is_online: bool = False

    @abstractmethod
    def complete(self, prompt: str) -> str:
        """Submit a prompt and return the response string."""
        ...

    def safe_complete(self, prompt: str) -> str:
        """Redact secrets before submitting; always use this over complete()."""
        clean_prompt = redact_secrets(prompt)
        return self.complete(clean_prompt)


class DeterministicProvider(BaseProvider):
    """Offline fallback — no network calls, fully deterministic output."""

    name = "deterministic"
    is_online = False

    def __init__(self, reason: str = "offline mode or no credentials") -> None:
        self._reason = reason

    def complete(self, prompt: str) -> str:  # noqa: ARG002
        # Never called with network; returns a structured offline stub.
        return (
            f"[DETERMINISTIC] Analysis performed without LLM ({self._reason}). "
            "Findings are based solely on static rules and advisory data."
        )


class OpenAIProvider(BaseProvider):
    """Optional OpenAI provider — only instantiated when OPENAI_API_KEY is present."""

    name = "openai"
    is_online = True
    _MAX_PROMPT_CHARS = 8_000  # conservative token-safe truncation

    def __init__(self, api_key: str, model: str = "gpt-4o-mini", timeout: int = 15) -> None:
        self._api_key = api_key
        self._model = model
        self._timeout = timeout

    def complete(self, prompt: str) -> str:
        """Call OpenAI chat completions endpoint."""
        try:
            import urllib.request
            import urllib.error
            import json

            truncated = prompt[: self._MAX_PROMPT_CHARS]
            payload = json.dumps({
                "model": self._model,
                "messages": [{"role": "user", "content": truncated}],
                "max_tokens": 512,
                "temperature": 0.0,
            }).encode()

            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=payload,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode())
                return data["choices"][0]["message"]["content"].strip()
        except Exception as exc:
            raise RuntimeError(f"OpenAI provider error: {exc}") from exc


def get_provider(config: ScanConfig, api_key_override: Optional[str] = None) -> BaseProvider:
    """Factory — returns the appropriate provider given scan config.

    Precedence:
    1. offline_mode → DeterministicProvider (no network, no exceptions)
    2. enable_llm=False → DeterministicProvider
    3. llm_provider='offline' or 'deterministic' → DeterministicProvider
    4. OPENAI_API_KEY in env (or api_key_override) → OpenAIProvider
    5. Fallback → DeterministicProvider (no credentials found)
    """
    if config.offline_mode:
        return DeterministicProvider(reason="offline mode")

    if not config.enable_llm:
        return DeterministicProvider(reason="LLM disabled via --no-llm")

    if config.llm_provider in ("offline", "deterministic", "mock"):
        return DeterministicProvider(reason=f"provider={config.llm_provider}")

    api_key = api_key_override or os.environ.get("OPENAI_API_KEY", "")
    if api_key and config.llm_provider in ("auto", "openai"):
        model = config.llm_model or "gpt-4o-mini"
        return OpenAIProvider(
            api_key=api_key,
            model=model,
            timeout=config.agent_timeout_seconds,
        )

    return DeterministicProvider(reason="no LLM credentials found in environment")

