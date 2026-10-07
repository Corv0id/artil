"""Evaluator and canary ledger (host side).

Deterministic canary detection is the ground truth for attack success --
never an LLM judge. Lives on the host, reads only the one-way event stream.
The agent can never read this state.
"""
