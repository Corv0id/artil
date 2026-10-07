"""Isolation / infrastructure layer (ARCHITECTURE layer 1).

Exposes :class:`~artil.infra.sandbox.Sandbox` and its helpers, used to build,
drive, and tear down one ephemeral rootless Podman container per run under a
deny-by-default posture (no network, read-only rootfs, scratch tmpfs, dropped
capabilities, resource caps).
"""

from artil.infra.sandbox import (
    DEFAULT_CPUS,
    DEFAULT_MEMORY,
    DEFAULT_NETWORK,
    DEFAULT_PIDS_LIMIT,
    DEFAULT_TMPFS,
    ExecResult,
    Sandbox,
    build_container_args,
    unique_sandbox_name,
)

__all__ = [
    "Sandbox",
    "ExecResult",
    "build_container_args",
    "unique_sandbox_name",
    "DEFAULT_NETWORK",
    "DEFAULT_TMPFS",
    "DEFAULT_PIDS_LIMIT",
    "DEFAULT_MEMORY",
    "DEFAULT_CPUS",
]
