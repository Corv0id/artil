"""Command-line entry point for artil.

Currently exposes `artis doctor`. Later subcommands: `run`, `report`.
"""

from __future__ import annotations

import argparse
import sys

from artil.doctor import run_doctor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="artil",
        description=(
            "Reproducible lab for measuring prompt-injection attacks and "
            "defenses on tool-using LLM agents (local models via Ollama)."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser(
        "doctor",
        help="check the local environment (Ollama, victim model, Podman)",
    )
    doctor.add_argument(
        "--ollama-url",
        default="http://localhost:11434",
        help="Ollama base URL (default: http://localhost:11434)",
    )
    doctor.add_argument(
        "--model",
        default="qwen3:4b",
        help="victim model that must be present (default: qwen3:4b)",
    )
    doctor.add_argument(
        "--podman-bin",
        default="podman",
        help="path to the podman binary (default: podman)",
    )
    doctor.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="network / subprocess timeout in seconds (default: 10)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "doctor":
        return run_doctor(
            sys.stdout,
            base_url=args.ollama_url,
            model=args.model,
            podman_bin=args.podman_bin,
            timeout=args.timeout,
        )
    # Unreachable: subparsers are required and only `doctor` exists yet.
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
