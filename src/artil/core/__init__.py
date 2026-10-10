"""Core instrumentation: one-way, integrity hash-chained telemetry.

Event bus emitting typed NDJSON records (``llm_request``/``response``,
``tool_call``/``result``, ``retrieval``, ``canary_contact``). Runs INSIDE the
sandbox and emits ONE WAY to the host -- see :mod:`artil.core.events`.

.. note::
   The chain is only tamper-evident if the *emitter* runs on the host, out of
   the agent's reach (DECISIONS.md / D-001).
"""

from artil.core.events import (
    EVENT_TYPES,
    ZERO_HASH,
    Event,
    EventLog,
    canonical_json,
    chain_hash,
    load_ndjson,
    verify_chain,
)

__all__ = [
    "EVENT_TYPES",
    "ZERO_HASH",
    "Event",
    "EventLog",
    "canonical_json",
    "chain_hash",
    "verify_chain",
    "load_ndjson",
]
