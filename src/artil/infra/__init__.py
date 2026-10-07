"""Isolation / infrastructure layer.

Builds and tears down ephemeral Podman containers per run with a tight
network policy (egress only to a host-controlled exfil sink), EROFS rootfs,
resource caps, and reproducible RunContext (seed, git hash, image digest,
model name+digest).
"""
