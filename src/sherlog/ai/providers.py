"""LLM providers behind one small interface: Anthropic (default), OpenAI-compatible, Ollama.

A provider starts a :class:`ChatSession` bound to a system prompt and tool set.
The session keeps the provider-native message history (so e.g. Claude's
thinking blocks are passed back unchanged) and returns normalized turns.
:class:`ReplayProvider` replays a recorded transcript for reproducible runs.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sherlog import __version__
from sherlog.core.config import get_setting
from sherlog.core.errors import SherlogError

DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 16000


class ProviderError(SherlogError):
    """The model call failed (auth, rate limit, network, refusal, bad response)."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ToolResult:
    call_id: str
    content: str
    is_error: bool = False


@dataclass
class Turn:
    """One model response, normalized across providers."""

    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = "end_turn"
    input_tokens: int = 0
    output_tokens: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "tool_calls": [
                {"id": c.id, "name": c.name, "arguments": c.arguments} for c in self.tool_calls
            ],
            "stop_reason": self.stop_reason,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Turn:
        return cls(
            text=d.get("text", ""),
            tool_calls=[
                ToolCall(c["id"], c["name"], c.get("arguments") or {})
                for c in d.get("tool_calls", [])
            ],
            stop_reason=d.get("stop_reason", "end_turn"),
            input_tokens=int(d.get("input_tokens", 0)),
            output_tokens=int(d.get("output_tokens", 0)),
        )


class ChatSession(ABC):
    @abstractmethod
    def send(
        self, *, user_text: str | None = None, tool_results: list[ToolResult] | None = None
    ) -> Turn:
        """Send a user message and/or tool results; return the model's next turn."""


class Provider(ABC):
    name: str
    model: str

    @abstractmethod
    def start(self, system: str, tools: list[ToolSpec]) -> ChatSession: ...


# --- Anthropic (official SDK) ---------------------------------------------------------------


class _AnthropicSession(ChatSession):
    def __init__(self, provider: AnthropicProvider, system: str, tools: list[ToolSpec]) -> None:
        self.p = provider
        self.system = system
        self.tools = [
            {"name": t.name, "description": t.description, "input_schema": t.parameters}
            for t in tools
        ]
        self.messages: list[dict[str, Any]] = []

    def send(
        self, *, user_text: str | None = None, tool_results: list[ToolResult] | None = None
    ) -> Turn:
        import anthropic

        content: list[dict[str, Any]] = [
            {
                "type": "tool_result",
                "tool_use_id": r.call_id,
                "content": r.content,
                "is_error": r.is_error,
            }
            for r in tool_results or []
        ]
        if user_text:
            content.append({"type": "text", "text": user_text})
        self.messages.append({"role": "user", "content": content})
        kwargs: dict[str, Any] = {
            "model": self.p.model,
            "max_tokens": MAX_TOKENS,
            "system": self.system,
            "messages": self.messages,
            # System prompt and tools are identical every round: cache the prefix.
            "cache_control": {"type": "ephemeral"},
        }
        if self.tools:
            kwargs["tools"] = self.tools
        if self.p.thinking:
            kwargs["thinking"] = {"type": "adaptive"}
        try:
            response = self.p.client.messages.create(**kwargs)
        except anthropic.AuthenticationError as exc:
            raise ProviderError(
                "Anthropic authentication failed: set ANTHROPIC_API_KEY, "
                "`sherlog config set ai.anthropic_key ...`, or run `ant auth login`"
            ) from exc
        except anthropic.PermissionDeniedError as exc:
            raise ProviderError(f"Anthropic permission denied: {exc.message}") from exc
        except anthropic.NotFoundError as exc:
            raise ProviderError(f"Anthropic model or endpoint not found ({self.p.model})") from exc
        except anthropic.RateLimitError as exc:
            raise ProviderError("Anthropic rate limit reached; try again later") from exc
        except anthropic.APIStatusError as exc:
            raise ProviderError(f"Anthropic API error {exc.status_code}: {exc.message}") from exc
        except anthropic.APIConnectionError as exc:
            raise ProviderError(f"Cannot reach the Anthropic API: {exc}") from exc

        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            raise ProviderError(f"The model declined to continue (refusal, category={category})")
        # Pass the full content back (thinking blocks included) on the next request.
        self.messages.append({"role": "assistant", "content": response.content})
        text = "".join(b.text for b in response.content if b.type == "text")
        calls = [
            ToolCall(b.id, b.name, dict(b.input) if isinstance(b.input, dict) else {})
            for b in response.content
            if b.type == "tool_use"
        ]
        usage = response.usage
        in_tokens = (
            (usage.input_tokens or 0)
            + (usage.cache_creation_input_tokens or 0)
            + (usage.cache_read_input_tokens or 0)
        )
        return Turn(text, calls, str(response.stop_reason), in_tokens, usage.output_tokens or 0)


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        *,
        thinking: bool = True,
        client: Any = None,
    ) -> None:
        self.model = model or DEFAULT_ANTHROPIC_MODEL
        # Haiku 4.5 and older models do not take adaptive thinking.
        self.thinking = thinking and not self.model.startswith("claude-haiku")
        if client is None:
            try:
                import anthropic
            except ImportError as exc:
                raise ProviderError(
                    "The Anthropic SDK is not installed: pip install 'sherlog[ai]'"
                ) from exc
            # Without a key the SDK resolves ANTHROPIC_API_KEY / auth token / `ant auth` profile.
            client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        self.client = client

    def start(self, system: str, tools: list[ToolSpec]) -> ChatSession:
        return _AnthropicSession(self, system, tools)


# --- OpenAI-compatible chat completions (also used for Ollama) -----------------------------

HttpPost = Callable[[str, dict[str, str], dict[str, Any], float], tuple[int, Any]]


def urllib_post(
    url: str, headers: dict[str, str], body: dict[str, Any], timeout: float
) -> tuple[int, Any]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"SherLog/{__version__}",
            **headers,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"null")
        except ValueError:
            return exc.code, None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderError(f"Cannot reach {url}: {exc}") from exc


class _OpenAISession(ChatSession):
    def __init__(
        self, provider: OpenAICompatibleProvider, system: str, tools: list[ToolSpec]
    ) -> None:
        self.p = provider
        self.tools = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            }
            for t in tools
        ]
        self.messages: list[dict[str, Any]] = [{"role": "system", "content": system}]

    def send(
        self, *, user_text: str | None = None, tool_results: list[ToolResult] | None = None
    ) -> Turn:
        for r in tool_results or []:
            self.messages.append({"role": "tool", "tool_call_id": r.call_id, "content": r.content})
        if user_text:
            self.messages.append({"role": "user", "content": user_text})
        body: dict[str, Any] = {"model": self.p.model, "messages": self.messages}
        if self.tools:
            body["tools"] = self.tools
            body["tool_choice"] = "auto"
        headers = {"Authorization": f"Bearer {self.p.api_key}"} if self.p.api_key else {}
        status, data = self.p.http_post(
            f"{self.p.base_url}/chat/completions", headers, body, self.p.timeout
        )
        if status != 200 or not isinstance(data, dict):
            detail = (data or {}).get("error") if isinstance(data, dict) else None
            raise ProviderError(f"{self.p.name} API error {status}: {detail}")
        try:
            choice = data["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError(f"{self.p.name}: unexpected response shape") from exc
        self.messages.append(
            {k: v for k, v in message.items() if k in ("role", "content", "tool_calls")}
        )
        calls = []
        for tc in message.get("tool_calls") or []:
            fn = tc.get("function") or {}
            raw_args = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            except ValueError:
                args = {"_invalid_json": raw_args}
            calls.append(ToolCall(tc.get("id") or fn.get("name", "call"), fn.get("name", ""), args))
        usage = data.get("usage") or {}
        return Turn(
            message.get("content") or "",
            calls,
            str(choice.get("finish_reason") or "stop"),
            int(usage.get("prompt_tokens") or 0),
            int(usage.get("completion_tokens") or 0),
        )


class OpenAICompatibleProvider(Provider):
    name = "openai"

    def __init__(
        self,
        model: str,
        *,
        base_url: str,
        api_key: str | None = None,
        timeout: float = 180.0,
        http_post: HttpPost = urllib_post,
    ) -> None:
        if not model:
            raise ProviderError(
                f"{self.name}: set a model with `sherlog config set ai.model <name>`"
            )
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.http_post = http_post

    def start(self, system: str, tools: list[ToolSpec]) -> ChatSession:
        return _OpenAISession(self, system, tools)


class OllamaProvider(OpenAICompatibleProvider):
    """Local models through Ollama's OpenAI-compatible endpoint (``/v1``)."""

    name = "ollama"

    def __init__(self, model: str, *, host: str, http_post: HttpPost = urllib_post) -> None:
        super().__init__(
            model, base_url=host.rstrip("/") + "/v1", timeout=600.0, http_post=http_post
        )


# --- Replay ---------------------------------------------------------------------------------


class _ReplaySession(ChatSession):
    def __init__(self, turns: list[Turn]) -> None:
        self.turns = turns
        self.pos = 0

    def send(
        self, *, user_text: str | None = None, tool_results: list[ToolResult] | None = None
    ) -> Turn:
        if self.pos >= len(self.turns):
            return Turn("(end of recorded transcript)", [], "end_turn")
        turn = self.turns[self.pos]
        self.pos += 1
        return turn


class ReplayProvider(Provider):
    """Returns recorded turns in order; the investigation and draft have separate queues."""

    name = "replay"

    def __init__(self, model: str, investigation: list[Turn], draft: list[Turn]) -> None:
        self.model = model
        self.queues = [investigation, draft]

    def start(self, system: str, tools: list[ToolSpec]) -> ChatSession:
        turns = self.queues.pop(0) if self.queues else []
        return _ReplaySession(turns)


def provider_from_config(name: str | None = None, model: str | None = None) -> Provider | None:
    """The configured provider, or None when AI is not configured."""
    name = (name or get_setting("ai.provider") or "").strip().lower()
    model = model or get_setting("ai.model")
    if not name:
        return None
    if name == "anthropic":
        return AnthropicProvider(
            model, get_setting("ai.anthropic_key"), thinking=bool(get_setting("ai.thinking"))
        )
    if name == "openai":
        return OpenAICompatibleProvider(
            model or "",
            base_url=get_setting("ai.openai_base_url"),
            api_key=get_setting("ai.openai_key"),
        )
    if name == "ollama":
        return OllamaProvider(model or "", host=get_setting("ai.ollama_url"))
    raise ProviderError(f"Unknown AI provider {name!r}; use anthropic, openai or ollama")
