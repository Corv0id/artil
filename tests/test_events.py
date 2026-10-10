"""Tests for artil.core.events (hash-chained telemetry)."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace

import pytest

from artil.core.events import (
    ZERO_HASH,
    Event,
    EventLog,
    chain_hash,
    load_ndjson,
    verify_chain,
)


class _Clock:
    """Monotonic-ish fake clock giving distinct, ordered timestamps."""

    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        self.t += 1.0
        return self.t


def test_chain_verifies_when_intact():
    log = EventLog(now=_Clock())
    log.emit("llm_request", model="qwen3:4b")
    log.emit("llm_response", text="ok")
    log.emit("tool_call", tool="fs.read", arg="/flag.txt")
    log.emit("canary_contact", channel="tool-result", canary="CANARY-x")
    assert verify_chain(log.events) is True


def test_first_event_prev_is_zero_hash():
    log = EventLog(now=_Clock())
    first = log.emit("llm_request", model="m")
    assert first.seq == 0
    assert first.prev == ZERO_HASH
    assert first.hash != ZERO_HASH


def test_unknown_event_type_is_rejected():
    log = EventLog(now=_Clock())
    with pytest.raises(ValueError, match="unknown event type"):
        log.emit("something_bogus")


def test_editing_an_event_is_detected():
    log = EventLog(now=_Clock())
    log.emit("llm_request", model="m")
    log.emit("tool_result", ok=True)
    log.emit("tool_call", tool="x")

    # Flip the stored hash on one event.
    tamper_hash = list(log.events)
    tamper_hash[1] = replace(tamper_hash[1], hash="0" * 64)
    assert verify_chain(tamper_hash) is False

    # ...and/or mutate a field of the payload without rehashing.
    tamper_data = list(log.events)
    tamper_data[2] = replace(tamper_data[2], data={**log.events[2].data, "tool": "y"})
    assert verify_chain(tamper_data) is False


def test_dropping_an_event_is_detected():
    log = EventLog(now=_Clock())
    for i in range(4):
        log.emit("tool_call", n=i)
    dropped = log.events[:1] + log.events[3:]
    assert verify_chain(dropped) is False


def test_reordering_is_detected():
    log = EventLog(now=_Clock())
    for i in range(3):
        log.emit("tool_result", n=i)
    assert verify_chain(list(reversed(log.events))) is False


def test_ndjson_round_trip_verifies_after_reload(tmp_path):
    path = tmp_path / "events.ndjson"
    with EventLog(path) as log:
        log.emit("llm_request", model="qwen3:4b", prompt="hi")
        log.emit("tool_call", tool="http_post", url="http://sink:9000")
        log.emit("canary_contact", canary="CANARY-abcdef", channel="tool-result")

    reloaded = load_ndjson(path)
    assert len(reloaded) == 3
    assert verify_chain(reloaded) is True
    assert reloaded[0].prev == ZERO_HASH
    assert reloaded[1].prev == reloaded[0].hash


def test_editing_a_line_on_disk_is_detected(tmp_path):
    path = tmp_path / "events.ndjson"
    with EventLog(path) as log:
        log.emit("tool_call", tool="x", a=1)
        log.emit("tool_result", ok=True)

    # Tamper the stored hash of the first line on disk.
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["hash"] = ("f" * 63) + ("0" if record["hash"][-1] != "0" else "1")
    lines[0] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert verify_chain(load_ndjson(path)) is False


def test_missing_event_on_disk_is_detected(tmp_path):
    path = tmp_path / "events.ndjson"
    with EventLog(path) as log:
        for i in range(3):
            log.emit("tool_call", n=i)
    lines = path.read_text(encoding="utf-8").splitlines()
    # Drop the middle line.
    path.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")
    assert verify_chain(load_ndjson(path)) is False


def test_canonical_json_is_key_order_independent():
    # Changing key order in data must not change the hash.
    h1 = chain_hash(seq=0, ts=1.0, type="tool_call", data={"a": 1, "b": 2}, prev=ZERO_HASH)
    h2 = chain_hash(seq=0, ts=1.0, type="tool_call", data={"b": 2, "a": 1}, prev=ZERO_HASH)
    assert h1 == h2


def test_empty_chain_verifies():
    assert verify_chain([]) is True


def test_event_is_frozen():
    e = Event(seq=0, ts=0.0, type="tool_call", data={}, prev=ZERO_HASH, hash="x")
    with pytest.raises(FrozenInstanceError):
        e.seq = 1
