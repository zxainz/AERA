"""LLM provider abstraction for AERA.

Phase 1 ships a generic OpenAI-compatible chat client (works with Z.ai / GLM
and any other compatible endpoint). Adding a new model backend means writing
one small subclass, not touching the pipeline.
"""
from __future__ import annotations

import os
import random
import time
from abc import ABC, abstractmethod

import requests


class LLMProvider(ABC):
    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Return the model's text response."""


class OpenAICompatibleProvider(LLMProvider):
    """Chat-completions client. Defaults target Z.ai's GLM endpoint.

    Any OpenAI-compatible endpoint works via AERA_LLM_BASE_URL, including a
    local Ollama server (http://localhost:11434/v1) -- see provider_from_env().
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout_s: int = 300,
        max_retries: int = 3,
    ) -> None:
        self.base_url = (
            base_url or os.environ.get("AERA_LLM_BASE_URL", "https://api.z.ai/api/paas/v4")
        ).rstrip("/")
        self.api_key = api_key or os.environ.get("AERA_LLM_API_KEY")
        if not self.api_key:
            if self._is_local_url(self.base_url):
                # Local servers (Ollama / llama.cpp) don't need a real key.
                self.api_key = "local"
            else:
                raise RuntimeError(
                    "AERA_LLM_API_KEY is not set. Put it in your .env file, "
                    "or use a local provider (AERA_LLM_PROVIDER=ollama)."
                )
        self.model = model or os.environ.get("AERA_LLM_MODEL", "glm-4.5")
        self.timeout_s = timeout_s
        self.max_retries = max(1, max_retries)

    @staticmethod
    def _is_local_url(url: str) -> bool:
        low = url.lower()
        return (
            "localhost" in low
            or "127.0.0.1" in low
            or low.startswith("http://192.168.")
            or low.startswith("http://10.")
        )

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """POST with exponential-backoff retries on transient failures."""
        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                resp = requests.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        "temperature": 0.2,
                    },
                    timeout=self.timeout_s,
                )
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"]
            except (requests.RequestException, KeyError, IndexError) as exc:
                last_exc = exc
                if attempt < self.max_retries - 1:
                    time.sleep(2**attempt + random.uniform(0, 1))
        raise RuntimeError(
            f"LLM request failed after {self.max_retries} attempts: {last_exc}"
        ) from last_exc


# ---------------------------------------------------------------------------
# Provider presets. AERA_LLM_PROVIDER selects one:
#   zai     (default) https://api.z.ai/api/paas/v4, model glm-4.5
#   ollama  local server http://localhost:11434/v1 (no key needed, NDA-safe)
#   custom  whatever AERA_LLM_BASE_URL / AERA_LLM_MODEL say
# ---------------------------------------------------------------------------

OLLAMA_BASE_URL = "http://localhost:11434/v1"
OLLAMA_DEFAULT_MODEL = "llama3.1"


def provider_from_env() -> OpenAICompatibleProvider:
    """Build the configured LLM provider from environment variables.

    Set AERA_LLM_PROVIDER=ollama (and optionally AERA_LLM_MODEL) to keep
    all code/analysis on the local machine -- nothing leaves the lab.
    Requires `ollama serve` running with the model pulled, e.g.:
        ollama pull llama3.1
    """
    provider = (os.environ.get("AERA_LLM_PROVIDER") or "zai").lower()
    if provider == "ollama":
        base_url = os.environ.get("AERA_LLM_BASE_URL", OLLAMA_BASE_URL)
        model = os.environ.get("AERA_LLM_MODEL", OLLAMA_DEFAULT_MODEL)
        try:
            requests.get(base_url.replace("/v1", "/api/tags"), timeout=5)
        except requests.RequestException as exc:
            raise RuntimeError(
                f"Ollama provider selected but no server answers at {base_url} "
                f"({exc}). Start it with `ollama serve` and pull a model, e.g. "
                f"`ollama pull {model}`."
            ) from exc
        return OpenAICompatibleProvider(base_url=base_url, model=model)
    return OpenAICompatibleProvider()
