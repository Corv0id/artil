"""Tests for the exfil sink (infra/sink.py)."""

from __future__ import annotations

import base64
import json
import socket
import time
import urllib.request
from types import SimpleNamespace

import pytest

from artil.core.events import EventLog, verify_chain
from artil.evaluator.canary import CanaryLedger, new_canary
from artil.infra.sink import MAX_BODY_BYTES, ExfilSink


@pytest.fixture
def ctx():
    """A fresh, active exfil sink with one seeded canary (exfil kind)."""
    ledger = CanaryLedger()
    log = EventLog()
    canary = new_canary("c1", seed=7)
    ledger.seed(canary)
    with ExfilSink(ledger, log) as sink:
        yield SimpleNamespace(ledger=ledger, log=log, canary=canary, sink=sink)


def _urllib(url, method="GET", data=None, headers=None):
    req = urllib.request.Request(url=url, data=data, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.getcode(), resp.read()


def _raw(host, port, request_bytes):
    """Send a raw HTTP/1.0 request; return the full raw response bytes."""
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(10)
        sock.sendall(request_bytes)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def test_canary_in_post_body(ctx):
    code, _ = _urllib(ctx.sink.url, method="POST", data=ctx.canary.token.encode())
    assert code == 200
    assert ctx.canary.id in ctx.ledger.triggered
    rec = ctx.sink.latest("/")
    assert rec is not None and rec.method == "POST"
    assert ctx.canary.id in rec.canary_ids
    assert any(e.type == "canary_contact" for e in ctx.log.events)


def test_canary_in_query_string(ctx):
    url = f"{ctx.sink.url}/leak?secret={ctx.canary.token}"
    code, _ = _urllib(url, method="GET")
    assert code == 200
    assert ctx.canary.id in ctx.ledger.triggered
    rec = ctx.sink.latest("/leak")
    assert rec is not None and ctx.canary.id in rec.canary_ids


def test_canary_in_header(ctx):
    code, _ = _urllib(ctx.sink.url + "/hdr", headers={"X-Canary": ctx.canary.token})
    assert ctx.canary.id in ctx.ledger.triggered
    rec = ctx.sink.latest("/hdr")
    assert any(k.lower() == "x-canary" and ctx.canary.token in v for k, v in rec.headers)
    assert ctx.canary.id in rec.canary_ids


def test_base64_token_inside_json_body(ctx):
    # The model base64-encodes a larger string that CONTAINS the token at an
    # odd byte offset, so only the alignment-robust variants match.
    inner = b"Xprefix-01" + ctx.canary.token.encode() + b"-trailing-22"
    assert len(b"Xprefix-01") % 3 != 0  # sanity: non-trivial alignment
    encoded = base64.b64encode(inner).decode()
    payload = json.dumps({"secret": encoded}).encode()
    code, _ = _urllib(ctx.sink.url, method="POST", data=payload)
    assert code == 200
    assert ctx.canary.id in ctx.ledger.triggered, "alignment-robust detection failed"


def test_no_canary_is_recorded_but_not_triggered(ctx):
    code, body = _urllib(ctx.sink.url + "/clean", method="POST", data=b"hello world")
    assert code == 200
    rec = ctx.sink.latest("/clean")
    assert rec is not None and rec.body == "hello world"
    assert rec.canary_ids == []
    assert ctx.ledger.triggered == set()
    assert not any(e.type == "canary_contact" for e in ctx.log.events)


def test_get_request(ctx):
    code, body = _urllib(ctx.sink.url + "/anything", method="GET")
    assert code == 200
    assert body == b"exfil-ok\n"
    rec = ctx.sink.latest("/anything")
    assert rec is not None and rec.method == "GET"


def test_oversized_body_is_capped_and_does_not_hang(ctx):
    # Content-Length claims more than the 1 MiB cap; the server must cap the
    # capture and must not block waiting for the oversized remainder.
    body = b"A" * (MAX_BODY_BYTES + 64)
    headers = f"POST /big HTTP/1.0\r\nContent-Length: {len(body)}\r\nHost: x\r\n\r\n".encode()
    response = _raw(ctx.sink.host, ctx.sink.port, headers + body[:MAX_BODY_BYTES])
    assert b"200" in response
    rec = ctx.sink.latest("/big")
    assert rec is not None
    assert len(rec.body) == MAX_BODY_BYTES  # capped exactly at 1 MiB


def test_response_identical_for_hit_and_nonhit(ctx):
    # Oracle-proof: the raw response must be byte-identical on a hit and a miss.
    hit_body = ctx.canary.token.encode()
    hit = _raw(
        ctx.sink.host,
        ctx.sink.port,
        f"POST /hit HTTP/1.0\r\nHost: x\r\nContent-Length: {len(hit_body)}\r\n\r\n".encode()
        + hit_body,
    )
    miss = _raw(ctx.sink.host, ctx.sink.port, b"GET /miss HTTP/1.0\r\nHost: x\r\n\r\n")
    assert hit == miss
    assert hit.split(b"\r\n", 1)[0] == b"HTTP/1.0 200 OK"
    assert b"exfil-ok" in hit
    # no per-request Date/Server header that would leak an oracle signal
    assert b"date:" not in hit.lower()
    assert b"server:" not in hit.lower()


def test_accepts_any_method(ctx):
    resp = _raw(ctx.sink.host, ctx.sink.port, b"PURGE /odd HTTP/1.0\r\nHost: x\r\n\r\n")
    assert b"200" in resp
    rec = ctx.sink.latest("/odd")
    assert rec is not None and rec.method == "PURGE"


def test_port_refused_after_exit():
    # A new, ephemeral sink; after the context exits the port must refuse.
    with ExfilSink(CanaryLedger(), EventLog()) as sink:
        host, port = sink.host, sink.port
        assert socket.create_connection((host, port), timeout=5)  # open while running
    time.sleep(0.05)
    with pytest.raises(OSError):
        socket.create_connection((host, port), timeout=2)


def test_event_chain_verifies_after_contact(ctx):
    code, _ = _urllib(ctx.sink.url, method="POST", data=ctx.canary.token.encode())
    assert code == 200
    assert ctx.canary.id in ctx.ledger.triggered
    assert verify_chain(ctx.log.events) is True
    contacts = [e for e in ctx.log.events if e.type == "canary_contact"]
    assert contacts and all(ctx.canary.id in e.data["canary_ids"] for e in contacts)


def test_sink_binds_localhost_only(ctx):
    assert ctx.sink.host == "127.0.0.1"
    assert ctx.sink.port != 0
