"""LLM backend abstraction (ARCHITECTURE layer 4: "Backend / LLM roles").

A single ``Backend`` interface is shared by the victim, attacker, judge, and
embedder roles; only the *model* behind it differs. Phase 1 ships
:class:`artil.backend.ollama.OllamaBackend`; an OpenAI-compatible backend (vLLM /
llama.cpp / cloud) can be dropped in later without touching the caller.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ToolCall:
    """One tool invocation emitted by the model.

    ``arguments`` is already normalized to a dict: Ollama (and other hosts) may
    return a dict *or* a JSON string, and :mod:`.ollama` coerces both to a dict
    here, so callers can rely on a mapping.
    """

    name: str
    arguments: dict


@dataclass(frozen=True)
class ChatResponse:
    """The normalized result of one ``chat`` call.

    ``raw`` is the complete backend payload (kept for the trace); ``eval_count``
    and ``total_ns`` are copied from the backend for cost/latency reporting.
    """

    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    thinking: str = ""
    raw: dict = field(default_factory=dict)
    eval_count: int = 0
    total_ns: int = 0


class BackendError(RuntimeError):
    """Raised by a backend on connection, HTTP, or JSON failures.

    A single exception type so the caller (the agent loop) has one thing to
    catch; the underlying cause is preserved in ``__cause__``.
    """


Message = dict  # a chat message is an arbitrary JSON-serializable dict


@runtime_checkable
class Backend(Protocol):
    """Minimal shared contract for an LLM backend.

    Implementations expose their model name as the attribute ``model`` and a
    ``chat`` method. The Phase 1 agent loop and every test fake satisfy it, so a
    real framework or a different model can be swapped behind the same call site.
    """

    model: str

    def chat(
        self,
        messages: list[Message],
        tools: list[dict] | None = None,
        *,
        seed: int | None = None,
        temperature: float = 0.0,
        num_ctx: int = 16384,
        think: bool = False,
    ) -> ChatResponse:
        """Send *messages* (with optional *tools*) and return a ChatResponse.

        ``temperature``, ``seed`` and ``num_ctx`` travel in Ollama's ``options``;
        ``think`` is a top-level field. See DECISIONS.md / D-002 for the Phase 1
        defaults (temperature 0.0, num_ctx 16384, think False).
        """
        ...
