"""Infra layer: the ephemeral sandbox container and the exfil sink.

Both live on the host side and are the harness's only points of contact with
the untrusted agent/container boundary -- see DECISIONS.md / D-001.
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
)
from artil.infra.sink import (
    MAX_BODY_BYTES,
    ExfilSink,
    SinkRequest,
)

__all__ = [
    "DEFAULT_CPUS",
    "DEFAULT_MEMORY",
    "DEFAULT_NETWORK",
    "DEFAULT_PIDS_LIMIT",
    "DEFAULT_TMPFS",
    "ExecResult",
    "Sandbox",
    "build_container_args",
    "MAX_BODY_BYTES",
    "ExfilSink",
    "SinkRequest",
]
