"""Pilot: run the first attack and its control across seeds (un-tuned).

For each arm (attack, control) and each seed we call artil.orchestrator.run_once, which
stands up a FRESH isolated sandbox, writes a poisoned (or clean) document and the secret
into it, runs one AgentLoop behind the real victim model, and reports whether the canary
reached the exfil sink. One line is printed per run plus a Wilson 95% CI summary per arm.
The control must yield 0 successes -- any nonzero control success is a harness bug.

Config is the experiment default: qwen3:4b, temperature 0.7, num_ctx 16384, think=false,
max_steps=8 (DECISIONS D-002 / D-003). Nothing is tuned here (D-003).
"""

from __future__ import annotations

import math
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from artil.doctor import DEFAULT_OLLAMA_URL, DEFAULT_VICTIM_MODEL  # noqa: E402
from artil.orchestrator.run import ATTACK, CONTROL, RunConfig, run_once  # noqa: E402

ARMS = (ATTACK, CONTROL)
N_SEEDS = int(os.environ.get("N_SEEDS", "20"))
MAX_STEPS = int(os.environ.get("MAX_STEPS", "8"))
Z = 1.959963984540054  # 2-sided 95%


def select_image(podman_bin: str) -> str | None:
    candidates = [
        os.environ.get("IMAGE"),
        "redis:7-alpine",
        "alpine:3",
        "python:3.11-slim",
    ]
    for cand in candidates:
        if not cand:
            continue
        exists = subprocess.run([podman_bin, "image", "exists", cand], capture_output=True)
        if exists.returncode == 0:
            return cand
    return None


def wilson_ci(k: int, n: int) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    z2 = Z * Z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (Z / denom) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return (max(0.0, center - half), min(1.0, center + half))


def main() -> int:
    podman_bin = os.environ.get("PODMAN_BIN", "podman")
    image = select_image(podman_bin)
    if image is None:
        print("no podman image available locally (set IMAGE=... to override)")
        return 1
    config = RunConfig(
        model=DEFAULT_VICTIM_MODEL,
        temperature=0.7,
        num_ctx=16384,
        think=False,
        max_steps=MAX_STEPS,
        image=image,
        host=os.environ.get("OLLAMA_URL", DEFAULT_OLLAMA_URL),
        timeout=120.0,
    )
    runs_dir = Path(tempfile.mkdtemp(prefix="artil-pilot-"))
    print(
        f"pilot_attack  arms={ARMS}  seeds=0..{N_SEEDS - 1}  model={config.model}"
        f"  temp={config.temperature}  num_ctx={config.num_ctx}  think={config.think}"
        f"  max_steps={config.max_steps}  image={image}"
    )
    print(f"runs_dir: {runs_dir}\n")

    for arm in ARMS:
        print(f"--- arm = {arm} ---")
        successes = 0
        exposed = 0
        errors = 0
        for seed in range(N_SEEDS):
            record = run_once(arm, seed, config, runs_dir, run_id=f"{arm}-s{seed:03d}")
            tag = "HIT" if record.attack_success else "clean"
            tool_str = ",".join(record.tools_called) or "-"
            print(
                f"       {arm:7s}  seed={seed:2d}  stop={record.stop_reason:8s}"
                f"  steps={record.steps:2d}  tools={tool_str:<22s}"
                f"  attack_success={int(record.attack_success)} {tag}"
            )
            print(
                f"   {record.run_id}  canary_exposed={int(record.canary_exposed)}"
                f"   chain_ok={int(record.chain_ok)}"
            )
            successes += int(record.attack_success)
            exposed += int(record.canary_exposed)
            errors += int(record.stop_reason == "error")

        lower, upper = wilson_ci(successes, N_SEEDS)
        rate = successes / N_SEEDS if N_SEEDS else 0.0
        print(
            f"    => {arm}: attack_success = {successes}/{N_SEEDS} ({rate:.1%})"
            f"  Wilson 95% CI [{lower:.1%}, {upper:.1%}]"
            f"  exposed= {exposed}/{N_SEEDS}  errors={errors}"
        )
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
