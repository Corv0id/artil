# Instructions for coding agents working on artil

artil is a lab that measures prompt-injection attacks and defenses on
tool-using LLM agents, running on local models (Ollama). The design source of
truth is docs/ARCHITECTURE.md. Read it once at the start of a session. Recorded
design decisions are in DECISIONS.md.

## Working rules
- Work on ONE task at a time. Stop when its acceptance criteria pass, report,
  and wait for my go-ahead. Do not start the next task.
- Do not edit docs/ARCHITECTURE.md without asking. Record new decisions in
  DECISIONS.md (date, decision, reason).
- Never claim a result you did not produce by running the code. Show real
  command output. If you could not verify something, say so plainly.
- If an environment problem blocks a check, do not silently substitute
  something else. Say what you changed and why.

## Code rules
- Python 3.12 managed with `uv`. The core package (src/artil) uses the
  standard library only. Ask before adding any dependency.
- Keep functions small and typed. No clever abstractions: other people must
  be able to read this code.
- Every new module gets tests in tests/. Tests that need Podman or Ollama use
  the `integration` marker and skip automatically when unavailable.
- Before saying a task is done, run `uv run pytest` and `uv run ruff check .`
  and fix everything. Then commit.

## Security design rules (do not violate)
- Attack success is decided by the canary ledger (src/artil/evaluator/canary.py),
  never by an LLM judge. An LLM judge may only be a secondary label.
- The evaluator, canary ledger, event log and exfil sink run on the HOST. The
  agent's tools run in the Podman container (--network=none). Never put
  evaluator code, ledger state or the event log where the agent can read or
  write it.
- The exfil sink must respond identically to hits and non-hits, so the agent
  cannot use it as an oracle.
- Default sandbox image is alpine:3. Do not change the default to make a test
  pass.

## Commands
- `uv sync`: install
- `uv run pytest`: tests
- `uv run ruff check .`: lint
- `uv run artil doctor`: check Ollama, models, Podman
- `./scripts/smoke_podman.sh`: prove the sandbox has no network
