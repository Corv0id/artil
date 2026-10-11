"""Ollama backend (Phase 1) -- one concrete :class:`.base.Backend` via urllib.

Talks to the local Ollama HTTP API (``POST /api/chat``) using the standard-library
:class:`urllib.request`. No third-party dependency. Every failure -- connection,
HTTP status, decode -- is normalized to the single :class:`.base.BackendError`.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from artil.backend.base import BackendError, ChatResponse, Message, ToolCall

DEFAULT_HOST = "http://localhost:11434"

# Phase 1 defaults (see DECISIONS.md / D-002). temperature 0.0 and think False make
# the victim deterministic; num_ctx is stated EXPLICITLY because Ollama's own
# default (often 2048–4096) can silently truncate long prompts.
DEFAULT_TEMPERATURE: float = 0.0
DEFAULT_NUM_CTX: int = 16384
DEFAULT_THINK: bool = False


class OllamaBackend:
    """A :class:`.base.Backend` backed by a local Ollama server."""

    def __init__(
        self,
        model: str,
        *,
        host: str = DEFAULT_HOST,
        timeout: float = 300.0,
        temperature: float = DEFAULT_TEMPERATURE,
        num_ctx: int = DEFAULT_NUM_CTX,
        think: bool = DEFAULT_THINK,
    ) -> None:
        self.model = model
        self._host = host.rstrip("/")
        self._timeout = timeout
        self._temperature = temperature
        self._num_ctx = num_ctx
        self._think = think

    @property
    def host(self) -> str:
        return self._host

    @property
    def temperature(self) -> float:
        return self._temperature

    @property
    def num_ctx(self) -> int:
        return self._num_ctx

    @property
    def think(self) -> bool:
        return self._think

    # --- the Backend contract ---------------------------------------------

    def chat(
        self,
        messages: list[Message],
        tools: list[dict] | None = None,
        *,
        seed: int | None = None,
        temperature: float | None = None,
        num_ctx: int | None = None,
        think: bool | None = None,
    ) -> ChatResponse:
        """Send one chat request to Ollama and return a normalized response.

        Per-call arguments fall back to the instance's Phase-1 defaults when left as``None``.
        Raises :class:`BackendError` on connection, HTTP, or JSON problems.
        """
        options = {
            "temperature": self._temperature if temperature is None else temperature,
            "num_ctx": self._num_ctx if num_ctx is None else num_ctx,
            "think": self._think if think is None else think,
        }
        # Ollama accepts a "seed" option; omit when not provided.
        if seed is not None:
            options["seed"] = seed

        body: dict = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": options,
            # "think" is a top-level field in Ollama's schema, not inside options.
            "think": self._think if think is None else think,
        }
        if tools:
            body["tools"] = tools

        raw = self._post(body)
        return _normalize(raw, self.model)

    def model_digest(self) -> str:
        """Return the digest of *model* from ``GET /api/tags`` (for snapshots)."""
        data = self._get_json(f"{self._host}/api/tags")
        models = data.get("models", []) if isinstance(data, dict) else data
        for model in models:
            name = model.get("name", "") if isinstance(model, dict) else str(model)
            if name == self.model or name == f"{self.model}:latest":
                digest = model.get("digest") if isinstance(model, dict) else None
                if digest:
                    return str(digest)
        raise BackendError(
            f"model {self.model!r} not found (or has no digest) in {self._host}/api/tags"
        )

    # --- HTTP transport ----------------------------------------------------

    def _post(self, body: dict) -> dict:
        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self._host}/api/chat",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise BackendError(f"HTTP {exc.code} from {self._host}/api/chat: {detail}") from exc
        except urllib.error.URLError as exc:
            raise BackendError(f"connection failed to {self._host}: {exc.reason}") from exc
        except TimeoutError as exc:  # noqa: B904
            raise BackendError(f"timed out talking to {self._host}") from exc
        return self._decode_json(raw, "chat")

    def _get_json(self, url: str) -> object:
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise BackendError(f"HTTP {exc.code} from {url}") from exc
        except urllib.error.URLError as exc:
            raise BackendError(f"connection failed to {url}: {exc.reason}") from exc
        except TimeoutError as exc:  # noqa: B904
            raise BackendError(f"timed out talking to {url}") from exc
        return self._decode_json(raw, "tags")

    @staticmethod
    def _decode_json(raw: bytes, what: str) -> object:
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise BackendError(f"cannot decode {what} response as JSON: {exc}") from exc


def _normalize(raw: dict, model: str = "") -> ChatResponse:
    """Normalize a raw Ollama ``/api/chat`` payload into a :class:`ChatResponse`."""
    if not isinstance(raw, dict):
        raise BackendError(f"unexpected non-object /api/chat response: {type(raw).__name__!r}")

    if raw.get("error"):
        raise BackendError(f"ollama error: {raw['error']}")
    if raw.get("done") is False and raw.get("error"):
        raise BackendError(f"ollama error: {raw['error']}")

    message = raw.get("message") or {}
    content = message.get("content") or raw.get("content") or ""
    if not isinstance(content, str):
        content = json.dumps(content)

    thinking = ""
    if isinstance(message.get("thinking"), str):
        thinking = message["thinking"]
    elif isinstance(raw.get("thinking"), str):
        thinking = raw["thinking"]

    tool_calls = _normalize_tool_calls(message.get("tool_calls") or [])

    eval_count = raw.get("eval_count") or 0
    total_ns = raw.get("total_ns", raw.get("eval_duration", raw.get("total_duration", 0)) or 0)

    return ChatResponse(
        content=content,
        tool_calls=tool_calls,
        thinking=thinking,
        raw=raw,
        eval_count=int(eval_count) if isinstance(eval_count, (int, float)) else 0,
        total_ns=int(total_ns) if isinstance(total_ns, (int, float)) else 0,
    )


def _normalize_tool_calls(raw_calls: list) -> list[ToolCall]:
    """Turn Ollama's tool_calls into ToolCall objects; coerce args dict/JSON-string."""
    calls: list[ToolCall] = []
    for item in raw_calls:
        if isinstance(item, dict):
            fn = item.get("function")
            name = item.get("name", "")
            args = item.get("arguments", {})
            # Ollama nests under "function"; some shapes put fields at top level.
            if isinstance(fn, dict):
                name = fn.get("name", name)
                args = fn.get("arguments", args)
            if not isinstance(args, dict):
                args = _coerce_arguments(args)
        else:
            name = str(item)
            args = {}
        calls.append(ToolCall(name=name, arguments=args))
    return calls


def _coerce_arguments(args: object) -> dict:
    """Force tool arguments to a dict (JSON string -> dict; anything else -> {})."""
    if isinstance(args, dict):
        return args
    if isinstance(args, str):
        try:
            parsed = json.loads(args)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}
