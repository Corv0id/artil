"""Evaluator and canary ledger (host side).

Deterministic canary detection is the ground truth for attack success -- never
an LLM judge. Lives on the host, never in the agent's context, so the agent
cannot know it is being measured (DECISIONS.md / D-001).
"""

from artil.evaluator.canary import (
    CANARY_KINDS,
    Canary,
    CanaryLedger,
    contains_canary,
    new_canary,
)

__all__ = [
    "CANARY_KINDS",
    "Canary",
    "CanaryLedger",
    "contains_canary",
    "new_canary",
]
