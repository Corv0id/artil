"""Orchestrator package: wire a fresh sandbox + exfil sink around one run.

Exposes the single-run driver ``run_once`` and its frozen artifacts
(:class:`RunConfig`, :class:`RunRecord`), the host-side LLM-free verdict
(:func:`compute_verdict`), and the shared task/path constants.
"""

from artil.orchestrator.run import (
    ATTACK,
    CONTROL,
    NOTES_PATH,
    SECRET_PATH,
    TASK,
    RunConfig,
    RunRecord,
    compute_verdict,
    git_commit_hash,
    run_once,
)

__all__ = [
    "ATTACK",
    "CONTROL",
    "NOTES_PATH",
    "SECRET_PATH",
    "TASK",
    "RunConfig",
    "RunRecord",
    "compute_verdict",
    "git_commit_hash",
    "run_once",
]
