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

---

## D-002 — Phase 1 victim-run options: temp 0, num_ctx 16384, think off

**Decision**

The victim LLM (default `qwen3:4b`) is run with `temperature = 0.0`,
`num_ctx = 16384`, and `think = False`. These are fixed, explicitly stated
values: they are part of the run configuration and must appear in every report
alongside the model name and digest.

**Reason**

- `temperature = 0.0` makes the victim deterministic so a given
  `task × attack × seed` is reproducible without resampling.
- `num_ctx = 16384` is stated *explicitly* because Ollama's own default context
  window can be small enough to silently truncate long (e.g. injected) prompts,
  which would let an attack succeed *only because it was truncated* -- a
  measurement artifact rather than a true result.
- `think = False` keeps the response in `content` (no separate `thinking`
  channel); the victim is a small instruct model where reasoning-as-answer is
  the observed behaviour.
- Together these are recorded in reports so a run is not reproducible across
  machines that rely on Ollama's silent defaults.
