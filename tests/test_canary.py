"""Tests for artil.evaluator.canary (deterministic canary ground truth)."""

from __future__ import annotations

import base64
import re

import pytest

from artil.evaluator.canary import (
    CANARY_KINDS,
    Canary,
    CanaryLedger,
    contains_canary,
    new_canary,
)

_TOKEN_SHAPE = re.compile(r"^CANARY-[0-9a-f]{16}$")


# --- canary construction ----------------------------------------------------


def test_token_shape_is_canary_prefix_plus_16_hex():
    canary = new_canary("c1", kind="exfil")
    assert _TOKEN_SHAPE.match(canary.token)
    assert canary.kind == "exfil"
    assert canary.id == "c1"


def test_same_seed_gives_same_token():
    a = new_canary("c1", seed=42)
    b = new_canary("cOther", seed=42)
    assert a.token == b.token


def test_different_seeds_given_different_tokens():
    a = new_canary("c1", seed=42)
    b = new_canary("c2", seed=43)
    assert a.token != b.token


def test_unknown_kind_is_rejected():
    with pytest.raises(ValueError, match="unknown canary kind"):
        new_canary("c1", kind="totally-bogus")
    with pytest.raises(ValueError, match="unknown canary kind"):
        Canary(id="c1", token="CANARY-x", kind="nope")
    for kind in CANARY_KINDS:
        assert new_canary("c", kind=kind).kind == kind  # all known kinds OK


def test_unseeded_tokens_are_random_and_distinct():
    seen = {new_canary(f"c{i}").token for i in range(50)}
    assert len(seen) == 50


# --- detection across encodings --------------------------------------------


def test_raw_token_is_detected():
    canary = new_canary("c1", seed=1)
    payload = f"leaking now: {canary.token} to the attacker"
    assert contains_canary(payload, canary) is True


def test_each_encoded_variant_is_detected():
    canary = new_canary("exfil-c", seed=7)
    raw = canary.token
    variants = {
        "raw": raw,
        "lower": raw.lower(),
        "upper": raw.upper(),
        "base64": base64.b64encode(raw.encode()).decode(),
        "urlsafe": base64.urlsafe_b64encode(raw.encode()).decode(),
        "hex": raw.encode().hex(),
        "reversed": raw[::-1],
    }
    for label, enc in variants.items():
        payload = f"the agent output {enc} somewhere"
        assert contains_canary(payload, canary) is True, f"failed to detect {label}"
        # and each listed variant really is distinct
    assert len(canary.variants()) == 7


def test_unrelated_text_gives_no_false_positive():
    canary = new_canary("c1", seed=1234)
    payloads = [
        "the agent read the file and summarized it",
        "canary is not present here, just the word canary",
        "CANARY-  (a fake, too short a token)",
        "http://127.0.0.1:11434/ benign exfil attempt, no token",
        "z" * 100_000,
    ]
    for p in payloads:
        assert contains_canary(p, canary) is False, f"false positive on: {p[:40]!r}"


# --- ledger -----------------------------------------------------------------


def test_ledger_records_the_channel_name():
    canary = new_canary("c1", seed=99)
    ledger = CanaryLedger()
    ledger.seed(canary)

    # benign channel -> nothing found
    assert ledger.observe("user-turn", "please do the task") == []
    assert ledger.triggered == set()

    # exfil channel carries the token
    found = ledger.observe("tool-return", f"here is data: {canary.token}")
    assert found == ["c1"]
    assert ledger.hits == [("c1", "tool-return")]
    assert "c1" in ledger.triggered


def test_ledger_distinguishes_channels_across_hits():
    ledger = CanaryLedger()
    c_a = new_canary("a", seed=1)
    c_b = new_canary("b", seed=2)
    ledger.seed(c_a)
    ledger.seed(c_b)

    assert ledger.observe("on-disk", c_a.token) == ["a"]
    assert ledger.observe("mcp-descriptor", f"x {c_b.token} y") == ["b"]
    assert ledger.hits == [("a", "on-disk"), ("b", "mcp-descriptor")]
    assert ledger.triggered == {"a", "b"}


def test_ledger_without_seeding_finds_nothing():
    ledger = CanaryLedger()
    assert ledger.observe("tool-return", "CANARY-abcdef0123456789") == []
    assert ledger.triggered == set()
