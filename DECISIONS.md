# DECISIONS

Project decision log for artil. New entries are **appended** at the bottom, each
numbered and dated, so the history stays diff-friendly. Rationale is recorded
alongside every choice.

---

## D-001 — Phase 1 host/agent split and the http_post tool channel

**Decision**

Phase 1: the agent loop runs on the host. fs/shell tools run inside the
network-less container. The http_post tool is executed by the host and may only
target the exfil sink.

**Reason**

The container needs no network, and telemetry cannot be tampered with by the
agent.
