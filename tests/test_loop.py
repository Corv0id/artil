"""Unit tests for the naive agent loop, using a scripted fake backend.

No Ollama is contacted here; the backend is scripted so behaviour is fully
deterministic.
"""

from __future__ import annotations

from artil.agent.loop import NAIVE_SYSTEM_PROMPT, AgentLoop, RunResult
from artil.backend.base import Backend, BackendError, ChatResponse, ToolCall
from artil.core.events import EventLog, verify_chain


class ScriptedBackend:
    """Return queued responses, then a default final answer so loops terminate."""

    def __init__(self, responses=None, model="fake:1"):
        self._responses = list(responses or [])
        self.model = model
        self.calls: list[dict] = []

    def chat(self, messages, tools=None, *, seed=None, temperature=0.0, num_ctx=16384, think=False):
        self.calls.append(
            {
                "messages": messages,
                "tools": tools,
                "seed": seed,
                "temperature": temperature,
                "num_ctx": num_ctx,
                "think": think,
            }
        )
        idx = len(self.calls) - 1
        if idx < len(self._responses):
            resp = self._responses[idx]
            if isinstance(resp, BaseException):
                raise resp
            return resp
        # ran out of scripted responses: a clean final answer so we terminate
        return ChatResponse(
            content="the end", tool_calls=[], thinking="", raw={}, eval_count=1, total_ns=10
        )

    def backend_model(self) -> str:
        return self.model


class AlwaysToolBackend:
    """Always request one tool call, so the loop hits the step cap."""

    model = "loop:1"

    def chat(self, messages, tools=None, **kwargs):
        return ChatResponse(
            content="calling",
            tool_calls=[ToolCall(name="read_file", arguments={"path": "/x"})],
            thinking="",
            raw={},
            eval_count=1,
            total_ns=5,
        )


class RaisingBackend:
    """Always raise a BackendError, to exercise the error path."""

    model = "boom"

    def chat(self, messages, tools=None, **kwargs):
        raise BackendError("kaboom")


class FakeToolBox:
    """A stand-in toolbox: records calls and returns canned, deterministic text."""

    def __init__(self, log):
        self.log = log
        self.calls: list[tuple] = []

    def schemas(self):
        return [
            {"type": "function", "function": {"name": "read_file"}},
            {"type": "function", "function": {"name": "run_shell"}},
            {"type": "function", "function": {"name": "http_post"}},
        ]

    def call(self, name, args):
        self.calls.append((name, args))
        result = SimpleResult(
            ok=name != "no_such_tool",
            text=(
                "unknown tool: 'no_such_tool'"
                if name == "no_such_tool"
                else f"result of {name}: {args}"
            ),
        )
        self.log.emit("tool_call", tool=name, arguments=args, sink=None)
        self.log.emit("tool_result", ok=result.ok, blocked=result.blocked, text=result.text)
        return result


class SimpleResult:
    """Minimal ToolResult-like object (only `.text` is read by the loop)."""

    def __init__(self, ok: bool, text: str):
        self.ok = ok
        self.text = text
        self.blocked = False


def _loop(backend, toolbox, log=None, **kw):
    log = log if log is not None else getattr(toolbox, "log", None) or EventLog()
    return AgentLoop(backend, toolbox, log, **kw)


# --- immediate / single-step -------------------------------------------------


def test_immediate_final_answer():
    log = EventLog()
    backend = ScriptedBackend([ChatResponse(content="hello", tool_calls=[], thinking="", raw={})])
    toolbox = FakeToolBox(log)
    result = _loop(backend, toolbox).run("say hi")
    assert isinstance(result, RunResult)
    assert result.stop_reason == "final"
    assert result.final_text == "hello"
    assert result.steps == 1
    assert result.tool_calls_made == 0
    assert verify_chain(log.events)


def test_stops_at_final_even_when_more_responses_queued():
    backend = ScriptedBackend(
        [
            ChatResponse(
                content="a", tool_calls=[ToolCall("read_file", {"path": "/x"})], thinking="", raw={}
            ),
            ChatResponse(content="done", tool_calls=[], thinking="", raw={}),
        ]
    )
    result = _loop(backend, FakeToolBox(EventLog())).run("task")
    assert result.stop_reason == "final"
    assert result.steps == 2
    assert result.tool_calls_made == 1


def test_one_tool_call_then_final_appends_tool_message():
    log = EventLog()
    backend = ScriptedBackend(
        [
            ChatResponse(
                content="", tool_calls=[ToolCall("read_file", {"path": "/x"})], thinking="", raw={}
            ),
            ChatResponse(content="first line is 42", tool_calls=[], thinking="", raw={}),
        ]
    )
    toolbox = FakeToolBox(log)
    result = _loop(backend, toolbox).run("read x")
    assert result.stop_reason == "final"
    assert result.tool_calls_made == 1
    # the final message list ends with assistant + tool + assistant(final)
    roles = [m["role"] for m in result.messages]
    assert roles == ["system", "user", "assistant", "tool", "assistant"]
    # the tool message has the task-specified shape
    tool_msg = result.messages[3]
    assert tool_msg["role"] == "tool"
    assert tool_msg["tool_name"] == "read_file"
    assert "result of read_file" in tool_msg["content"]


# --- tool failures do not abort the loop -------------------------------------


def test_unknown_tool_is_recorded_and_loop_continues():
    log = EventLog()
    backend = ScriptedBackend(
        [
            ChatResponse(
                content="", tool_calls=[ToolCall("no_such_tool", {"x": 1})], thinking="", raw={}
            ),
            ChatResponse(content="fell through", tool_calls=[], thinking="", raw={}),
        ]
    )
    toolbox = FakeToolBox(log)
    result = _loop(backend, toolbox).run("do something")
    assert result.stop_reason == "final"
    assert result.tool_calls_made == 1
    assert "no_such_tool" in toolbox.calls[0][0]
    assert any(m["role"] == "tool" and "unknown" in m["content"] for m in result.messages)


# --- max_steps ---------------------------------------------------------------


def test_max_steps_cap():
    log = EventLog()
    result = _loop(AlwaysToolBackend(), FakeToolBox(log), max_steps=5).run("loop")
    assert result.stop_reason == "max_steps"
    assert result.steps == 5
    assert result.tool_calls_made == 5


# --- backend error -----------------------------------------------------------


def test_backend_error_yields_error_run():
    log = EventLog()
    result = _loop(RaisingBackend(), FakeToolBox(log)).run("task")
    assert result.stop_reason == "error"
    assert "kaboom" in result.final_text
    assert result.steps == 1  # the failed request still counts as one step
    assert verify_chain(log.events)


# --- instrumentation ---------------------------------------------------------


def test_event_order_and_hash_chain():
    log = EventLog()
    backend = ScriptedBackend(
        [
            ChatResponse(
                content="", tool_calls=[ToolCall("read_file", {"path": "/x"})], thinking="", raw={}
            ),
            ChatResponse(content="ok", tool_calls=[], thinking="", raw={}),
        ]
    )
    _loop(backend, FakeToolBox(log)).run("task")
    types = [e.type for e in log.events]
    # first turn: llm_request, llm_response, tool_call, tool_result
    assert types[:4] == ["llm_request", "llm_response", "tool_call", "tool_result"]
    # tool results are interleaved with calls
    assert types[4:6] == ["llm_request", "llm_response"]
    assert verify_chain(log.events)
    assert all(len(e.hash) == 64 for e in log.events)


def test_llm_request_sends_only_new_messages():
    log = EventLog()
    backend = ScriptedBackend(
        [
            ChatResponse(
                content="", tool_calls=[ToolCall("read_file", {"path": "/x"})], thinking="", raw={}
            ),
            ChatResponse(content="ok", tool_calls=[], thinking="", raw={}),
        ]
    )
    _loop(backend, FakeToolBox(log)).run("task")
    requests = [e for e in log.events if e.type == "llm_request"]
    assert len(requests) == 2
    # the first request carries only system + user
    first_new = requests[0].data["new_messages"]
    assert [m["role"] for m in first_new] == ["system", "user"]
    # the second request carries only the tool result, not the whole history
    second_new = requests[1].data["new_messages"]
    assert [m["role"] for m in second_new] == ["tool"]
    assert "system" not in [m["role"] for m in second_new]


def test_message_shapes_passed_to_backend():
    log = EventLog()
    backend = ScriptedBackend([ChatResponse(content="ok", tool_calls=[], thinking="", raw={})])
    _loop(backend, FakeToolBox(log)).run("task")
    sent = backend.calls[0]["messages"]
    # system + user, and they are plain dict messages
    assert sent[0]["role"] == "system"
    assert sent[1]["role"] == "user"
    assert backend.calls[0]["tools"] == FakeToolBox(EventLog()).schemas()


def test_options_record_determinism_settings():
    log = EventLog()
    backend = ScriptedBackend([ChatResponse(content="ok", tool_calls=[], thinking="", raw={})])
    _loop(backend, FakeToolBox(log), seed=7, temperature=0.0, num_ctx=16384, think=False).run("t")
    req = [e for e in log.events if e.type == "llm_request"][0]
    opts = req.data["options"]
    assert opts["temperature"] == 0.0
    assert opts["num_ctx"] == 16384
    assert opts["think"] is False
    assert opts["seed"] == 7


# --- the naive prompt must leak nothing about the experiment -----------------


def test_naive_system_prompt_mentions_no_experiment_terms():
    lower = NAIVE_SYSTEM_PROMPT.lower()
    for forbidden in ("canary", "sink", "exfil", "attack", "injec", "prompt injection", "evaluat"):
        assert forbidden not in lower, f"system prompt leaked the term: {forbidden!r}"


def test_system_prompt_lists_the_three_tools():
    for tool in ("read_file", "run_shell", "http_post"):
        assert tool in NAIVE_SYSTEM_PROMPT, f"system prompt should mention {tool}"


def test_backend_is_runtime_checkable():
    assert isinstance(ScriptedBackend(), Backend)
