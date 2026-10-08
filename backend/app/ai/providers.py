"""LLM provider abstraction. The conversation format is provider-neutral: a list of `{"role", "content"}` messages whose content
is a string or a list of blocks (`text`, `tool_use`, `tool_result`). Adapters translate to/from their wire format. The model only
ever sees tool *schemas* and tool *results*; credentials and platform internals never enter a prompt."""

from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from app.core.config import Settings


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
        self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]], max_tokens: int = 2048
    ) -> LLMResponse: ...


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, settings: Settings) -> None:
        self.model = settings.ai_model
        self._base = settings.ai_base_url.rstrip("/")
        self._key = settings.anthropic_api_key
        self._timeout = settings.ai_timeout_s

    async def complete(
        self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]], max_tokens: int = 2048
    ) -> LLMResponse:
        body: dict[str, Any] = {"model": self.model, "max_tokens": max_tokens, "system": system, "messages": messages}
        if tools:
            body["tools"] = tools
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


def build_provider(settings: Settings) -> LLMProvider | None:
    if settings.ai_provider == "anthropic" and settings.anthropic_api_key:
        return AnthropicProvider(settings)
    return None
