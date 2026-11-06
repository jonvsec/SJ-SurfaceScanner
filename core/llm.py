"""
core/llm.py — LLM router with data classification enforcement.

Routing logic (non-negotiable):
  CONFIDENTIAL data → Ollama local ONLY, zero exceptions
  Context < limit   → Ollama local (preferred)
  Context >= limit  → OpenRouter (public data only, large context fallback)

All callers must pass data_classification. Passing "CONFIDENTIAL" to a
function that would route to OpenRouter raises ClassificationError instead
of silently sending private data to an external API.

Usage:
    router = LLMRouter(config)
    text = await router.complete(prompt, classification="SEMI-PUBLIC")
    obj  = await router.complete_json(prompt, classification="PUBLIC")
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

import structlog

from core.config import Config

log = structlog.get_logger(__name__)


class ClassificationError(Exception):
    """Raised when CONFIDENTIAL data would be routed to an external API."""


class LLMError(Exception):
    """Raised when all LLM backends fail."""


# Rough token estimate: 1 token ≈ 4 chars. Used to decide local vs cloud.
def _estimate_tokens(text: str) -> int:
    return len(text) // 4


class LLMRouter:
    """
    Routes LLM calls to the appropriate backend based on data classification
    and context size. Instantiate once, share across the pipeline.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._ollama_client = None
        self._openai_client = None

    def _get_ollama(self):
        if self._ollama_client is None:
            import ollama
            self._ollama_client = ollama.AsyncClient(
                host=self._config.ollama.host
            )
        return self._ollama_client

    def _get_openrouter(self):
        if self._openai_client is None:
            from openai import AsyncOpenAI
            api_key = os.environ.get("OPENROUTER_API_KEY", "")
            if not api_key:
                raise LLMError(
                    "OPENROUTER_API_KEY is not set — cannot use OpenRouter fallback"
                )
            self._openai_client = AsyncOpenAI(
                api_key=api_key,
                base_url="https://openrouter.ai/api/v1",
            )
        return self._openai_client

    def _choose_backend(self, prompt: str, classification: str) -> str:
        """
        Returns "ollama" or "openrouter".
        CONFIDENTIAL always returns "ollama". Never returns "openrouter" for
        CONFIDENTIAL — ClassificationError is raised instead if it would.
        """
        if classification == "CONFIDENTIAL":
            return "ollama"

        tokens = _estimate_tokens(prompt)
        if tokens < self._config.ollama.context_limit:
            return "ollama"

        # Large context + non-CONFIDENTIAL → OpenRouter
        if classification == "CONFIDENTIAL":
            # Defensive: this branch should never be reached
            raise ClassificationError(
                "CONFIDENTIAL data cannot be sent to OpenRouter regardless of context size"
            )
        return "openrouter"

    async def complete(
        self,
        prompt: str,
        *,
        classification: str,
        system: str | None = None,
        temperature: float = 0.2,
    ) -> str:
        """
        Generate a text completion.

        Args:
            prompt:         User prompt text.
            classification: DATA CLASSIFICATION — "CONFIDENTIAL", "SEMI-PUBLIC",
                            or "PUBLIC". Controls which backend is used.
            system:         Optional system prompt.
            temperature:    Sampling temperature (default 0.2 for factual tasks).

        Returns:
            Response text as a string.

        Raises:
            ClassificationError: if CONFIDENTIAL data would be sent externally.
            LLMError: if all backends fail.
        """
        backend = self._choose_backend(prompt, classification)
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        log.debug(
            "llm.complete",
            backend=backend,
            classification=classification,
            est_tokens=_estimate_tokens(prompt),
        )

        if backend == "ollama":
            return await self._ollama_complete(messages, temperature)
        return await self._openrouter_complete(messages, temperature)

    async def complete_json(
        self,
        prompt: str,
        *,
        classification: str,
        system: str | None = None,
    ) -> Any:
        """
        Generate a completion and parse the result as JSON.

        The prompt should instruct the model to reply with valid JSON only.
        Strips markdown code fences if the model wraps its response.

        Returns:
            Parsed Python object (dict, list, etc.)

        Raises:
            LLMError: if the response cannot be parsed as JSON after retries.
        """
        json_system = (
            (system + "\n" if system else "") +
            "Reply with valid JSON only. No explanation, no markdown fences."
        )
        raw = await self.complete(
            prompt,
            classification=classification,
            system=json_system,
        )
        return _parse_json_response(raw)

    async def _ollama_complete(
        self,
        messages: list[dict],
        temperature: float,
    ) -> str:
        client = self._get_ollama()
        cfg    = self._config.ollama

        # qwen3 supports /think and /no_think tokens to control thinking mode.
        # For structured JSON output we always want no_think (fast, deterministic).
        # For kill chain / narrative we want think (deeper reasoning).
        options: dict = {"temperature": temperature, "num_ctx": cfg.context_limit}
        if not cfg.thinking_mode and "qwen3" in cfg.model:
            # Inject /no_think as system prefix — Qwen3 specific toggle
            messages = _inject_thinking_toggle(messages, think=False)

        try:
            response = await client.chat(
                model=cfg.model,
                messages=messages,
                options=options,
            )
            return response.message.content
        except Exception as exc:
            log.warning("llm.ollama_failed", error=str(exc), model=cfg.model)
            # Try fallback model
            if cfg.fallback_model and cfg.fallback_model != cfg.model:
                try:
                    response = await client.chat(
                        model=cfg.fallback_model,
                        messages=messages,
                        options={"temperature": temperature},
                    )
                    log.info("llm.ollama_fallback_used", model=cfg.fallback_model)
                    return response.message.content
                except Exception as exc2:
                    log.error("llm.ollama_fallback_failed", error=str(exc2))
            raise LLMError(f"Ollama failed: {exc}") from exc

    async def _openrouter_complete(
        self,
        messages: list[dict],
        temperature: float,
    ) -> str:
        client = self._get_openrouter()
        model  = self._config.openrouter.model
        try:
            response = await client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            log.error("llm.openrouter_failed", error=str(exc), model=model)
            raise LLMError(f"OpenRouter failed: {exc}") from exc


    async def complete_with_thinking(
        self,
        prompt: str,
        *,
        classification: str,
        system: str | None = None,
    ) -> str:
        """
        Use the heavy model (qwen2.5:72b) for deep reasoning tasks like kill chain
        narrative generation. Falls back to primary model if heavy model not available.
        Always stays local — CONFIDENTIAL reasoning never leaves the machine.
        """
        cfg      = self._config.ollama
        # Use heavy_model for maximum quality on complex reasoning tasks
        model    = getattr(cfg, "heavy_model", cfg.model)
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        # qwen3 models support /think toggle for explicit reasoning mode
        if "qwen3" in model:
            messages = _inject_thinking_toggle(messages, think=True)

        options = {"temperature": 0.6, "num_ctx": cfg.context_limit}
        try:
            client   = self._get_ollama()
            response = await client.chat(
                model=model,
                messages=messages,
                options=options,
            )
            content = response.message.content
            import re
            content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
            return content
        except Exception as exc:
            log.warning("llm.thinking_failed", error=str(exc))
            # Fall back to standard complete
            return await self.complete(prompt, classification=classification, system=system)


def _inject_thinking_toggle(messages: list[dict], think: bool) -> list[dict]:
    """
    Prepend /think or /no_think to the first user message for qwen3.
    Qwen3 uses these tokens to switch between reasoning and fast modes.
    See: https://qwen.readthedocs.io/en/latest/getting_started/thinking.html
    """
    token = "/think" if think else "/no_think"
    result = []
    first_user_found = False
    for msg in messages:
        if msg["role"] == "user" and not first_user_found:
            result.append({**msg, "content": f"{token}\n\n{msg['content']}"})
            first_user_found = True
        else:
            result.append(msg)
    return result


def _parse_json_response(raw: str) -> Any:
    """Strip markdown fences and parse JSON. Raises LLMError on failure."""
    text = raw.strip()
    # Strip ```json ... ``` or ``` ... ```
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE)
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise LLMError(f"LLM response is not valid JSON: {exc}\nRaw: {raw[:200]}") from exc
