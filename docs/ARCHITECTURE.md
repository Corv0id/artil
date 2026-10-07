# ATRI — Agent Red-team & Threat Intelligence / Lab — Architecture & Stack

> Status: DESIGN (Phase 1.1 blueprint). No code generated yet.
> First principles: (1) framework independent of Pi; (2) instrument-under-test
> fully separated from the evaluator; (3) deterministic canary ground truth, not
> an LLM judge; (4) one-way, out-of-band telemetry.

## Local environment (probed 2026-09-29)
- Ollama 0.34.2 running. Owned: `qwen3.8:27b-mlx` (18 GB, heavy attacker/judge),
  `qwen3-embedding:4b` (RAG). **Missing: a small aligned instruct victim** → plan
  `qwen3:4b` (fast) or `llama3.1:8b-instruct` (comparable to published numbers).
- Podman 6.1.0 rootless, machine `applehv` present but **never started** → first
  setup step: `podman machine start`.
- No Docker. Python via `uv` (3.12). MacBook M5 Pro / 48 GB / 840 GB free.
- Attacker/uncensored lane: pull a ready abliterated model
  (`huihui-ai/Hermes-3-Llama-3.2-3B-abliterated`) or abliterate `llama-3.1-8b`
  later with OBLITERATUS (MIT core). Different family from victim ⇒ no
  "the model is just unaligned" confound.

## Tech stack
| Layer | Choice | Why |
|---|---|---|
| Host orchestration | Python 3.12 + `uv` | user-chosen; reproducible dep pinning |
| Isolation | **Podman rootless**, ephemeral per-run containers, `--network=none` default, EROFS rootfs + tmpfs, resource caps | no docker daemon; untrusted agent/tools can't reach host |
| Exfil sink | host-controlled localhost listener (TCP/HTTP) that accepts canary contact; only channel the container may egress to | attack success = canary observed *here* (deterministic) |
| LLM backend | `Backend` interface: `Ollama` (Phase 1) ↔ OpenAI-compatible (vLLM/llama.cpp/cloud later) | swap attacker/victim/judge freely |
| RAG | `qwen3-embedding:4b` retriever + pluggable embedding backend | owned; contrast w/ `bge`/`nomic` |
| Telemetry | NDJSON one-way event stream, integrity hash-chained | evaluator reads only this; never in agent context |
| Reports | static JSON + Markdown (+ HTML later) in `runs/<ts>/` | reproducible, diffable |
| Tests | `pytest` | |

## Architecture (layers, bottom-up)
1. **Isolation / infra** (`infra/`): build+tear-down ephemeral Podman container
   per run; network policy (egress only to exfil sink); mounts (canary files,
   event sink); caps; `RunContext` (seed, git hash, image digest, model name+
   digest). Deterministic snapshots ⇒ reproducibility.
2. **Agent-under-test** (`agent/`): one loop, two axes — **capability** (model)
   × **hardening profile** (naive / guarded / hardened) → free A-B. Implements a
   `Tool` protocol (fs, shell, db, http→exfil, mcp, memory). Default = our naive,
   fully-instrumented loop; optional adapter = a real framework (LangChain/CrewAI
   style) for realism/transferability.
3. **Instrumentation / telemetry** (`core/`): event bus → NDJSON
   (`llm_request/response`, `tool_call/result`, `retrieval`, `canary_contact`).
   Canary seeding pre-run; integrity hash-chain. Runs INSIDE the sandbox, emits
   ONE WAY to host.
4. **Backend / LLM roles**: victim, attacker, judge, embedder — same interface,
   different model. Attacker ≠ victim by default (see below).
5. **Attack catalog** (`attacks/`): each attack = a module with
   `catalog entry {id, category, channel, generator, success_canary}`. Channels:
   user-turn, tool-return, retrieved-doc (RAG), on-disk file, MCP descriptor.
   Mode A = static catalog; Mode B = **autonomous red-team agent** (a 2nd LLM
   synthesizes/iterates attacks, h4rm3l/GPTFuzz style) — out of band.
6. **Defense catalog** (`defenses/`): middleware on the same pipeline — input
   filter, output filter, tool-output sanitizer, tool allowlist (the first real
   defense in Phase 1), prompt-guard, detector. Run undefended vs defended.
7. **Evaluator / measurement** (`evaluator/`): deterministic canary detection
   (ground truth) + metrics (ASR, PUA, NRP≈PUA·(1−ASR), steps, latency, cost,
   re-run variance w/ bootstrap CIs). Optional LLM judge = *secondary* label,
   always subordinate to the canary.
8. **Orchestration** (`orchestrator/` + CLI `atril run --scenario …`): a
   Scenario = DAG cross product (benign task × attack × profile × defense ×
   victim × model × seed × n_runs) → a run matrix → aggregate report.
9. **Reporting** (`reports/`): static HTML/MD dashboard (Phase 1), thin
   read-only web viewer later.

### The pivotal decision
**The agent and its tools live INSIDE the sandbox; the canary ledger and judge
live OUTSIDE on the host and read only the one-way event stream.** The evaluator
never appears in the agent's context. This is what makes results trustworthy
(no measurement-contamination, agent can't "know" it's被测). ARPIbench's pattern
(real agent + container + exfil to a controlled server) is the reference for the
Phase 1 end-to-end.

## Data models
- `Scenario` config: task, attack(s), profile, defense(s), model, victim, seed, n_runs
- `Run`: one execution → full trace + metrics
- `Event`: telemetry record (typed, hash-chained)
- `Canary`: id, token, kind ∈ {exfil, prompt-leak, forbidden-action, data-tamper}
- `Attack` / `Defense` catalog entries (above)
- `Report`: per-run + aggregate matrix

## Attack-catalog references (study, don't depend on)
- AgentDojo (4 domains, ~7 variants) — structure/schema
- MSB arXiv 2510.15994 (12 MCP attack types) — MCP lane
- RAG Security Bench arXiv 2505.18543 (13 attacks, 7 defenses) — RAG lane
- ARPIbench — reflected-injection end-to-end in a container (Phase 1 template)
- InjecAgent — ASR-valid/ASR-all split (metric)
- JailbreakBench / h4rm3l / GPTFuzz — jailbreak catalog + synthesis
- Finding to carry in: **inverse scaling** — more capable models can be MORE
  susceptible (MSB, ARPIbench). A smaller/less-aligned victim is a valid,
  interesting target.

## Phase 1 (≈1 week) — accepted scope
isolation + one-way telemetry → canary ledger → swappable backend → naive agent
loop + shell/fs tools + exfil sink → ONE end-to-end direct/indirect-injection
attack (exfil of a canary via tool return) → reproducible report + host-side
event log + benign-task success check (PUA sanity). **Deferred:** RAG/MCP/
memory poisoning, full attack catalog, hardening A-B, LLM judge.

## Open decisions
1. Victim model: `qwen3:4b` (OK)? — need to pull a small aligned instruct victim.
2. Attacker: pull ready `Hermes-3-3B-abliterated` now, vs abliterate
   `llama-3.1-8b` yourself later?
3. Adopt MSB + RAG Security Bench as the RAG/MCP catalog references?
4. Podman machine start now as first step?
