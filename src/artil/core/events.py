"""Tamper-evident, hash-chained telemetry (ARCHITECTURE layer 3, ``core``).

Each :class:`Event` carries the SHA-256 of its own canonical fields *and* its
predecessor's hash, forming an integrity hash-chain. Any edit to a past event,
or the dropping/reordering of an event, breaks the chain and
:func:`verify_chain` returns ``False``.

.. note::
   The chain only protects the log **if the emitter runs on the host, out of
   the agent's reach.** If the agent could write the log, it could simply forge
   the hashes. This is a direct consequence of DECISIONS.md / D-001 (the agent
   loop runs on the host; the container needs no network; telemetry cannot be
   tampered with by the agent).
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

ZERO_HASH = "0" * 64

#: The recognized telemetry event types (one-way event stream, ARCHITECTURE 3).
EVENT_TYPES = (
    "llm_request",
    "llm_response",
    "tool_call",
    "tool_result",
    "retrieval",
    "canary_contact",
)
_VALID_TYPES = frozenset(EVENT_TYPES)


def canonical_json(obj) -> bytes:
    """Encode *obj* as canonical JSON: sorted keys, compact separators, utf-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def chain_hash(*, seq: int, ts: float, type: str, data: dict, prev: str) -> str:
    """Return the SHA-256 hex digest of the canonical JSON of the 5 fields."""
    payload = {"seq": seq, "ts": ts, "type": type, "data": data, "prev": prev}
    return hashlib.sha256(canonical_json(payload)).hexdigest()


@dataclass(frozen=True)
class Event:
    """One tamper-evident record. ``hash`` chains to ``prev`` (the prior hash).

    The first event of a log has ``prev == ZERO_HASH``.
    """

    seq: int
    ts: float
    type: str
    data: dict
    prev: str
    hash: str

    def to_json(self) -> dict:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "type": self.type,
            "data": self.data,
            "prev": self.prev,
            "hash": self.hash,
        }

    @classmethod
    def from_json(cls, d: dict) -> Event:
        return cls(
            seq=d["seq"],
            ts=d["ts"],
            type=d["type"],
            data=d["data"],
            prev=d["prev"],
            hash=d["hash"],
        )


def verify_chain(events: Sequence[Event]) -> bool:
    """Return True iff *events* form an intact, in-order hash chain.

    Detects: edited events (hash or any field), dropped events, and reordering.
    """
    expected_prev = ZERO_HASH
    for expected_seq, event in enumerate(events):
        if event.seq != expected_seq:
            return False
        if event.prev != expected_prev:
            return False
        recomputed = chain_hash(
            seq=event.seq, ts=event.ts, type=event.type, data=event.data, prev=event.prev
        )
        if recomputed != event.hash:
            return False
        expected_prev = event.hash
    return True


def load_ndjson(path: str | Path) -> list[Event]:
    """Load a list of :class:`Event` from an NDJSON file (blank lines skipped)."""
    events: list[Event] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped:
                events.append(Event.from_json(json.loads(stripped)))
    return events


class EventLog:
    """Append-only, one-way event log.

    :meth:`emit` appends to memory and, when a *path* is given, writes one NDJSON
    line per event and **flushes immediately**. Usable as a context manager.
    """

    def __init__(self, path: str | Path | None = None, now=time.time) -> None:
        self.path = Path(path) if path is not None else None
        self.events: list[Event] = []
        self._now = now
        self._fh = None
        if self.path is not None:
            self._fh = open(self.path, "a", encoding="utf-8")

    def emit(self, type: str, **data) -> Event:
        """Append an event of *type* carrying *data*; return the created Event."""
        if type not in _VALID_TYPES:
            raise ValueError(f"unknown event type {type!r}; expected one of {EVENT_TYPES!r}")
        prev = self.events[-1].hash if self.events else ZERO_HASH
        seq = len(self.events)
        ts = self._now()
        event = Event(
            seq=seq,
            ts=ts,
            type=type,
            data=data,
            prev=prev,
            hash=chain_hash(seq=seq, ts=ts, type=type, data=data, prev=prev),
        )
        self.events.append(event)
        if self._fh is not None:
            self._fh.write(json.dumps(event.to_json(), separators=(",", ":")) + "\n")
            self._fh.flush()
        return event

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> EventLog:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
        return None
