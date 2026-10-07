"""Tests for artil.cli dispatch (does not touch the network)."""

from __future__ import annotations

import pytest

from artil import cli


def test_parse_args_defaults(monkeypatch):
    # `doctor` maps onto run_doctor; replace it to avoid real I/O.
    captured = {}

    def fake_run_doctor(out, **kwargs):
        captured.update(kwargs)
        out.write("ok\n")
        return 0

    monkeypatch.setattr(cli, "run_doctor", fake_run_doctor)
    rc = cli.main(["doctor", "--model", "llama3.1:8b-instruct", "--ollama-url", "http://x/y"])
    assert rc == 0
    assert captured["model"] == "llama3.1:8b-instruct"
    assert captured["base_url"] == "http://x/y"


def test_main_returns_failure_code(monkeypatch):
    def fake_run_doctor(out, **kwargs):
        out.write("failed\n")
        return 1

    monkeypatch.setattr(cli, "run_doctor", fake_run_doctor)
    assert cli.main(["doctor"]) == 1


def test_no_command_errors(capsys):
    with pytest.raises(SystemExit):
        cli.main([])
