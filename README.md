# artil — Agent Red-team & Threat Intelligence / Lab

> **Status: early development — no results yet.** This repository currently
> contains only setup and environment checks. No attack or defense
> experiments have run; nothing here is a measurement finding.

A reproducible lab that measures **prompt-injection attacks and defenses** on
tool-using LLM agents, running on **local models via Ollama**. The goal is
trustworthy, diffable, reproducible numbers — not vibes.

## Design principles

These four invariants (see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md))
govern everything in this project:

1. **Framework-independent.** The lab does not depend on Pi (or any particular
   agent framework); agent under test is just a loop, swappable for a real
   framework later for transferability.
2. **Instrument-under-test fully separated from the evaluator.** The agent and
   its tools run *inside* the Podman sandbox. The canary ledger and any judge
   live *on the host* and never appear in the agent's context — the agent can
   not "know" it is being measured.
3. **Deterministic canary ground truth, not an LLM judge.** Attack success is
   decided by an out-of-band canary observed by the host, never by asking an
   LLM whether the attack "looked" successful.
4. **One-way, out-of-band telemetry.** The sandbox emits a single, integrity
   hash-chained NDJSON event stream *out* to the host. The host only reads; the
   evaluator state is never mounted where the agent can read it.

Isolation is provided by **rootless Podman** with ephemeral per-run containers,
`--network=none` by default (egress only to a host-controlled exfil sink),
EROFS rootfs + tmpfs, and resource caps.

## Layout

```
src/artil/
  backend/     # swappable LLM Backend (Ollama now; OpenAI-compatible later)
  core/        # one-way, hash-chained telemetry (event bus / NDJSON)
  evaluator/   # canary ledger + metrics (host side, deterministic ground truth)
  infra/       # Podman build/tear-down, network policy, reproducibility
scripts/       # ops scripts
tests/         # pytest
runs/          # generated reports (gitignored except .gitkeep)
docs/          # design
```

## Quickstart

```bash
# 1. Set up the environment (uv-managed Python 3.12)
cd artil
uv sync

# 2. Ensure Ollama is running with the victim + embedder models:
curl -fsS http://localhost:11434 >/dev/null   # or: ollama serve
# models: qwen3:4b (victim), qwen3-embedding:4b (RAG)

# 3. Start the Podman machine and smoke-test isolation:
./scripts/smoke_podman.sh

# 4. Run the environment doctor:
uv run artil doctor
```

## Testing

```bash
uv run pytest
uv run ruff check .
```

## Roadmap (Phase 1)

Isolation + one-way telemetry → canary ledger → swappable backend → naive agent
loop with shell/fs tools + an exfil sink → **one** end-to-end
direct/indirect-injection attack (canary exfil via tool return) → reproducible
report + host-side event log + a benign-task success check. See
`docs/ARCHITECTURE.md` for the full blueprint.
