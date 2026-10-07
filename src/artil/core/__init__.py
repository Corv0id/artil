"""Core instrumentation: one-way, integrity hash-chained telemetry.

Event bus emitting typed NDJSON records (llm_request/response,
tool_call/result, retrieval, canary_contact). Runs INSIDE the sandbox and
emits ONE WAY to the host. Standard library only.
"""
