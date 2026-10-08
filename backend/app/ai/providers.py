"""LLM provider abstraction. The conversation format is provider-neutral: a list of `{"role", "content"}` messages whose content
is a string or a list of blocks (`text`, `tool_use`, `tool_result`). Adapters translate to/from their wire format. The model only
ever sees tool *schemas* and tool *results*; credentials and platform internals never enter a prompt."""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from app.core.config import Settings

RETRY_DELAYS_S = (0, 3, 8, 15)
MIN_TOKENS = 4096  # reasoning models spend the budget thinking; a tiny cap would leave an empty answer


class ProviderUnavailable(Exception):
    """No provider configured, or the provider call failed. The message is safe to show to users."""


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = ""
    input_tokens: int = 0
    output_tokens: int = 0

    def blocks(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = [{"type": "text", "text": self.text}] if self.text else []
        out += [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.input} for c in self.tool_calls]
        return out


class LLMProvider(Protocol):
    name: str
    model: str

    async def complete(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int = 2048,
        force_tool: str | None = None,
    ) -> LLMResponse: ...


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, settings: Settings) -> None:
        self.model = settings.ai_model
        self._base = settings.ai_base_url.rstrip("/")
        self._key = settings.anthropic_api_key
        self._timeout = settings.ai_timeout_s

    async def complete(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int = 2048,
        force_tool: str | None = None,
    ) -> LLMResponse:
        body: dict[str, Any] = {"model": self.model, "max_tokens": max_tokens, "system": system, "messages": messages}
        if tools:
            body["tools"] = tools
            if force_tool:
                body["tool_choice"] = {"type": "tool", "name": force_tool}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._base}/v1/messages",
                    json=body,
                    headers={"x-api-key": self._key, "anthropic-version": "2023-06-01"},
                )
        except httpx.HTTPError:
            raise ProviderUnavailable("The AI provider could not be reached") from None
        if resp.status_code in (401, 403):
            raise ProviderUnavailable("The AI provider rejected the configured credentials")
        if resp.status_code == 429:
            raise ProviderUnavailable("The AI provider is rate limiting requests; try again shortly")
        if resp.status_code >= 400:
            raise ProviderUnavailable(f"The AI provider returned an error (HTTP {resp.status_code})")
        data = resp.json()
        out = LLMResponse(
            stop_reason=str(data.get("stop_reason") or ""),
            input_tokens=int((data.get("usage") or {}).get("input_tokens") or 0),
            output_tokens=int((data.get("usage") or {}).get("output_tokens") or 0),
        )
        for block in data.get("content") or []:
            if block.get("type") == "text":
                out.text += str(block.get("text") or "")
            elif block.get("type") == "tool_use":
                inp = block.get("input")
                out.tool_calls.append(
                    ToolCall(id=str(block["id"]), name=str(block["name"]), input=inp if isinstance(inp, dict) else {})
                )
        return out


def _to_openai_messages(system: str, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Provider-neutral blocks -> OpenAI chat messages (assistant tool_calls; tool results as `tool` role messages)."""
    out: list[dict[str, Any]] = [{"role": "system", "content": system}]
    for m in messages:
        content = m["content"]
        if isinstance(content, str):
            out.append({"role": m["role"], "content": content})
            continue
        text = "".join(str(b.get("text") or "") for b in content if b.get("type") == "text")
        if m["role"] == "assistant":
            msg: dict[str, Any] = {"role": "assistant", "content": text or None}
            calls = [
                {
                    "id": b["id"],
                    "type": "function",
                    "function": {"name": b["name"], "arguments": json.dumps(b.get("input") or {})},
                }
                for b in content
                if b.get("type") == "tool_use"
            ]
            if calls:
                msg["tool_calls"] = calls
            out.append(msg)
        else:
            for b in content:
                if b.get("type") == "tool_result":
                    c = b.get("content")
                    out.append(
                        {
                            "role": "tool",
                            "tool_call_id": b["tool_use_id"],
                            "content": c if isinstance(c, str) else json.dumps(c),
                        }
                    )
            if text:
                out.append({"role": "user", "content": text})
    return out


class OpenRouterProvider:
    """OpenAI-compatible chat completions (OpenRouter). Same neutral interface; only schemas and results cross the wire."""

    name = "openrouter"

    def __init__(self, settings: Settings) -> None:
        self.model = settings.ai_model
        self._base = settings.openrouter_base_url.rstrip("/")
        self._key = settings.openrouter_api_key
        self._timeout = settings.ai_timeout_s

    async def complete(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int = 2048,
        force_tool: str | None = None,
    ) -> LLMResponse:
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max(max_tokens, MIN_TOKENS),
            "reasoning": {"effort": "low"},
            "messages": _to_openai_messages(system, messages),
        }
        if tools and force_tool:
            body["tool_choice"] = {"type": "function", "function": {"name": force_tool}}
        if tools:
            body["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "parameters": t.get("input_schema") or {"type": "object", "properties": {}},
                    },
                }
                for t in tools
            ]
        resp: httpx.Response | None = None
        for attempt, delay in enumerate(RETRY_DELAYS_S):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(
                        f"{self._base}/chat/completions", json=body, headers={"Authorization": f"Bearer {self._key}"}
                    )
            except httpx.HTTPError:
                raise ProviderUnavailable("The AI provider could not be reached") from None
            if resp.status_code not in (429, 502, 503) or attempt == len(RETRY_DELAYS_S) - 1:
                break
            await asyncio.sleep(delay)  # shared upstream pools throttle in bursts
        assert resp is not None
        if resp.status_code in (401, 403):
            raise ProviderUnavailable("The AI provider rejected the configured credentials")
        if resp.status_code == 429:
            raise ProviderUnavailable("The AI provider is rate limiting requests; try again shortly")
        if resp.status_code >= 400:
            raise ProviderUnavailable(f"The AI provider returned an error (HTTP {resp.status_code})")
        try:
            data = resp.json()
            choice = (data.get("choices") or [{}])[0]
            msg = choice.get("message") or {}
        except (ValueError, AttributeError, IndexError):
            raise ProviderUnavailable("The AI provider returned an unreadable response") from None
        usage = data.get("usage") or {}
        out = LLMResponse(
            text=str(msg.get("content") or ""),
            stop_reason="tool_use" if msg.get("tool_calls") else str(choice.get("finish_reason") or ""),
            input_tokens=int(usage.get("prompt_tokens") or 0),
            output_tokens=int(usage.get("completion_tokens") or 0),
        )
        for c in msg.get("tool_calls") or []:
            fn = c.get("function") or {}
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except ValueError:
                args = {}
            out.tool_calls.append(
                ToolCall(
                    id=str(c.get("id") or f"call_{len(out.tool_calls)}"),
                    name=str(fn.get("name") or ""),
                    input=args if isinstance(args, dict) else {},
                )
            )
        return out


def build_provider(settings: Settings) -> LLMProvider | None:
    if settings.ai_provider == "anthropic" and settings.anthropic_api_key:
        return AnthropicProvider(settings)
    if settings.ai_provider == "openrouter" and settings.openrouter_api_key:
        return OpenRouterProvider(settings)
    return None
