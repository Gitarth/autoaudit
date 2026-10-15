"""
Bring-your-own-key LLM access: Anthropic Messages API and any
OpenAI-compatible Chat Completions endpoint (OpenAI, Azure OpenAI, vLLM,
Ollama, LM Studio, OpenRouter, ...).

Keys are only ever read from environment variables, never from arguments, so
they do not end up in shell history, logs or result files.
"""

from __future__ import annotations

import json
import logging
import os
import random
import threading
import time
from dataclasses import dataclass, field

import requests

log = logging.getLogger(__name__)

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODELS = {"anthropic": "claude-sonnet-5-5"}
DEFAULT_KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}
RETRY_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 529}


class LLMError(RuntimeError):
    pass


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    requests: int = 0

    def add(self, other: Usage) -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens
        self.requests += other.requests

    def cost(self, price_in: float | None, price_out: float | None) -> float | None:
        """USD, given prices per million input/output tokens (cache tokens billed as input)."""
        if price_in is None or price_out is None:
            return None
        tokens_in = self.input_tokens + self.cache_read_tokens + self.cache_write_tokens
        return round((tokens_in * price_in + self.output_tokens * price_out) / 1e6, 4)


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict


@dataclass
class Message:
    """Provider-neutral conversation turn.
    role: "user" (text), "assistant" (text and/or tool_calls) or "tool" (results: [(call_id, content)],
    plus optional text sent alongside the results)."""

    role: str
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    results: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict  # JSON schema of the arguments object


@dataclass
class Reply:
    text: str
    usage: Usage
    model: str
    stop_reason: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)

    def as_message(self) -> Message:
        return Message("assistant", self.text, list(self.tool_calls))


@dataclass
class Provider:
    """Base class: retries, usage accounting, a shared HTTP session."""

    model: str
    api_key: str = field(repr=False)
    max_tokens: int = 2048
    temperature: float = 0.0
    timeout: int = 120
    max_retries: int = 5
    session: requests.Session = field(default_factory=requests.Session, repr=False)
    total: Usage = field(default_factory=Usage)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    name = "base"

    def complete(self, system: str, user: str) -> Reply:
        return self.chat(system, [Message("user", user)])

    def chat(self, system: str, messages: list[Message], tools: list[Tool] | None = None) -> Reply:
        reply = self._with_retries(lambda: self._chat(system, messages, tools or []))
        with self._lock:
            self.total.add(reply.usage)
        return reply

    def _chat(self, system: str, messages: list[Message], tools: list[Tool]) -> Reply:  # pragma: no cover
        raise NotImplementedError

    def _post(self, url: str, headers: dict, body: dict) -> dict:
        res = self.session.post(url, headers=headers, json=body, timeout=self.timeout)
        if res.status_code in RETRY_STATUS:
            raise _Retryable(res.status_code, res.headers.get("retry-after"), res.text[:300])
        if res.status_code >= 400:
            raise LLMError(f"{self.name} API error {res.status_code}: {res.text[:500]}")
        return res.json()

    def _with_retries(self, fn):
        for attempt in range(self.max_retries + 1):
            try:
                return fn()
            except (_Retryable, requests.ConnectionError, requests.Timeout) as err:
                if attempt == self.max_retries:
                    raise LLMError(f"{self.name}: giving up after {attempt + 1} attempts: {err}") from err
                wait = _retry_after(err) or min(60, 2**attempt) + random.random()
                log.warning("%s: %s; retrying in %.1fs", self.name, err, wait)
                time.sleep(wait)
        raise AssertionError("unreachable")


class _Retryable(Exception):
    def __init__(self, status: int, retry_after: str | None, body: str):
        super().__init__(f"HTTP {status}: {body}")
        self.retry_after = retry_after


def _retry_after(err: Exception) -> float | None:
    value = getattr(err, "retry_after", None)
    try:
        return min(float(value), 120.0) if value else None
    except ValueError:
        return None


@dataclass
class AnthropicProvider(Provider):
    url: str = ANTHROPIC_URL
    name = "anthropic"

    def _chat(self, system: str, messages: list[Message], tools: list[Tool]) -> Reply:
        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            # The system prompt is identical for every alert: cache it.
            "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            "messages": [self._wire(m) for m in messages],
        }
        if tools:
            body["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.parameters} for t in tools
            ]
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        data = self._post(self.url, headers, body)
        blocks = data.get("content", [])
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        calls = [
            ToolCall(b["id"], b["name"], b.get("input") or {}) for b in blocks if b.get("type") == "tool_use"
        ]
        u = data.get("usage", {})
        usage = Usage(
            input_tokens=u.get("input_tokens", 0),
            output_tokens=u.get("output_tokens", 0),
            cache_read_tokens=u.get("cache_read_input_tokens") or 0,
            cache_write_tokens=u.get("cache_creation_input_tokens") or 0,
            requests=1,
        )
        return Reply(text, usage, data.get("model", self.model), data.get("stop_reason"), calls)

    @staticmethod
    def _wire(m: Message) -> dict:
        if m.role == "user":
            return {"role": "user", "content": m.text}
        if m.role == "assistant":
            content = [{"type": "text", "text": m.text}] if m.text else []
            content += [
                {"type": "tool_use", "id": c.id, "name": c.name, "input": c.args} for c in m.tool_calls
            ]
            return {"role": "assistant", "content": content}
        content = [{"type": "tool_result", "tool_use_id": cid, "content": out} for cid, out in m.results]
        if m.text:
            content.append({"type": "text", "text": m.text})
        return {"role": "user", "content": content}


@dataclass
class OpenAICompatProvider(Provider):
    base_url: str = "https://api.openai.com/v1"
    # Newer OpenAI models reject `max_tokens`; most compatible servers only know it.
    max_tokens_field: str = "max_tokens"
    name = "openai"

    def _chat(self, system: str, messages: list[Message], tools: list[Tool]) -> Reply:
        wire = [{"role": "system", "content": system}]
        for m in messages:
            wire.extend(self._wire(m))
        body = {
            "model": self.model,
            self.max_tokens_field: self.max_tokens,
            "temperature": self.temperature,
            "messages": wire,
        }
        if tools:
            body["tools"] = [
                {
                    "type": "function",
                    "function": {"name": t.name, "description": t.description, "parameters": t.parameters},
                }
                for t in tools
            ]
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        data = self._post(self.base_url.rstrip("/") + "/chat/completions", headers, body)
        choices = data.get("choices") or []
        if not choices:
            raise LLMError(f"openai-compatible API returned no choices: {str(data)[:300]}")
        msg = choices[0].get("message", {})
        calls = []
        for c in msg.get("tool_calls") or []:
            fn = c.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {"_invalid_arguments": fn.get("arguments")}
            calls.append(
                ToolCall(c.get("id", ""), fn.get("name", ""), args if isinstance(args, dict) else {})
            )
        u = data.get("usage") or {}
        cached = (u.get("prompt_tokens_details") or {}).get("cached_tokens") or 0
        usage = Usage(
            input_tokens=max(0, u.get("prompt_tokens", 0) - cached),
            output_tokens=u.get("completion_tokens", 0),
            cache_read_tokens=cached,
            requests=1,
        )
        return Reply(
            msg.get("content") or "",
            usage,
            data.get("model", self.model),
            choices[0].get("finish_reason"),
            calls,
        )

    @staticmethod
    def _wire(m: Message) -> list[dict]:
        if m.role == "user":
            return [{"role": "user", "content": m.text}]
        if m.role == "assistant":
            out = {"role": "assistant", "content": m.text or None}
            if m.tool_calls:
                out["tool_calls"] = [
                    {
                        "id": c.id,
                        "type": "function",
                        "function": {"name": c.name, "arguments": json.dumps(c.args)},
                    }
                    for c in m.tool_calls
                ]
            return [out]
        out = [{"role": "tool", "tool_call_id": cid, "content": res} for cid, res in m.results]
        return out + ([{"role": "user", "content": m.text}] if m.text else [])


def make_provider(
    provider: str,
    model: str | None = None,
    base_url: str | None = None,
    api_key_env: str | None = None,
    max_tokens_field: str = "max_tokens",
    **kwargs,
) -> Provider:
    """Build a provider; the key comes from `api_key_env` (or the provider's default variable)."""
    if provider not in DEFAULT_KEY_ENV:
        raise ValueError(f"unknown provider {provider!r}; use 'anthropic' or 'openai'")
    env = api_key_env or DEFAULT_KEY_ENV[provider]
    key = os.environ.get(env, "")
    if not key and not (provider == "openai" and base_url):  # local servers often need no key
        raise LLMError(f"no API key: set the {env} environment variable")
    model = model or DEFAULT_MODELS.get(provider)
    if not model:
        raise ValueError("--model is required for openai-compatible providers")
    if provider == "anthropic":
        return AnthropicProvider(model=model, api_key=key, url=base_url or ANTHROPIC_URL, **kwargs)
    return OpenAICompatProvider(
        model=model,
        api_key=key or "none",
        base_url=base_url or "https://api.openai.com/v1",
        max_tokens_field=max_tokens_field,
        **kwargs,
    )
