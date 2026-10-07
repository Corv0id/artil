"""Tests for artil.doctor (env health checks, std-lib only)."""

from __future__ import annotations

import json
import urllib.error

from artil import doctor
from artil.doctor import check_model_present, check_podman_running


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _runner(returning):
    def fake(*_args, **_kwargs):
        return returning

    return fake


def _raise_not_found(*_args, **_kwargs):
    raise FileNotFoundError("podman not found")


class _CaptureStream:
    def __init__(self):
        self._buf = []

    def write(self, s):
        self._buf.append(s)

    def getvalue(self):
        return "".join(self._buf)


# --- model_is_present -------------------------------------------------------


def test_model_is_present_exact():
    models = [{"name": "qwen3:4b"}, {"name": "qwen3-embedding:4b"}]
    assert doctor.model_is_present(models, "qwen3:4b") is True


def test_model_is_present_suffix_and_base():
    assert doctor.model_is_present([{"name": "qwen3:4b-quant"}], "qwen3:4b") is True
    assert doctor.model_is_present([{"name": "qwen3:latest"}], "qwen3:4b") is True


def test_model_is_present_absent():
    assert doctor.model_is_present([{"name": "llama3.1:8b"}], "qwen3:4b") is False


# --- check_ollama_reachable -------------------------------------------------


def test_ollama_reachable_ok():
    models = [{"name": "qwen3:4b"}]
    result, got = doctor.check_ollama_reachable(
        "http://example",
        1.0,
        json_get=lambda *a, **k: {},
        models_get=lambda *a, **k: models,
    )
    assert result.passed is True
    assert got == models
    assert "reachable" in result.line()


def test_ollama_unreachable():
    def boom(*_a, **_k):
        raise urllib.error.URLError("connection refused")

    result, got = doctor.check_ollama_reachable(
        "http://nope", 1.0, json_get=boom, models_get=doctor.get_ollama_models
    )
    assert result.passed is False
    assert got == []
    assert "not reachable" in result.line()


# --- check_model_present ----------------------------------------------------


def test_check_model_present_pass():
    r = check_model_present([{"name": "qwen3:4b"}], "qwen3:4b")
    assert r.passed is True and "present" in r.line()


def test_check_model_present_fail():
    r = check_model_present([{"name": "other:1"}], "qwen3:4b")
    assert r.passed is False and "not found" in r.line()


# --- check_podman_running ---------------------------------------------------


def test_podman_running_yes():
    body = json.dumps([{"Name": "podman-machine-default", "Running": True}])
    r = check_podman_running("podman", runner=_runner(FakeProc(0, stdout=body)))
    assert r.passed is True and "running" in r.line()


def test_podman_running_none_up():
    body = json.dumps([{"Name": "m", "Running": False}])
    r = check_podman_running("podman", runner=_runner(FakeProc(0, stdout=body)))
    assert r.passed is False and "no running machine" in r.line()


def test_podman_not_found():
    r = check_podman_running("podman", runner=_raise_not_found)
    assert r.passed is False and "not found" in r.line()


def test_podman_list_error():
    r = check_podman_running(
        "podman", runner=_runner(FakeProc(1, stdout="", stderr="Error: cannot connect"))
    )
    assert r.passed is False and "failed" in r.line()


def test_podman_bad_json():
    r = check_podman_running("podman", runner=_runner(FakeProc(0, stdout="not json")))
    assert r.passed is False and "parse" in r.line().lower()


# --- run_doctor end-to-end --------------------------------------------------


def test_run_doctor_all_pass():
    capture = _CaptureStream()
    result = doctor.run_doctor(
        capture,
        json_get=lambda *a, **k: {},
        models_get=lambda *a, **k: [{"name": "qwen3:4b"}],
        runner=lambda *a, **k: FakeProc(0, stdout='[{"Name": "m", "Running": true}]'),
    )
    assert result == 0
    assert "all 3 check(s) passed" in capture.getvalue().replace("\n", " ")


def test_run_doctor_one_fail():
    capture = _CaptureStream()
    result = doctor.run_doctor(
        capture,
        json_get=lambda *a, **k: {},
        models_get=lambda *a, **k: [{"name": "qwen3:4b"}],
        runner=_raise_not_found,
    )
    assert result == 1
    assert "failed" in capture.getvalue()
