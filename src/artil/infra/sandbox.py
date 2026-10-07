"""Ephemeral Podman sandbox for the agent-under-test (ARCHITECTURE layer 1).

Responsibilities:
  * build + tear-down an *ephemeral, rootless* Podman container per run;
  * enforce a deny-by-default posture: ``--network=none`` (no egress at all --
    the exfil sink is reached out-of-band by the host, see DECISIONS.md),
    ``--read-only`` rootfs, ``--tmpfs`` scratch, ``--cap-drop=ALL``,
    ``--security-opt no-new-privileges``, and CPU/memory/PID caps;
  * execute commands inside the sandbox with a hard ``timeout``;
  * record the *resolved* image id/digest for reproducible snapshots.

Only the Python standard library and the ``podman`` CLI (via :mod:`subprocess`)
are used. The pure :func:`build_container_args` is unit-testable without podman.

macOS/Podman caveat: only host paths under the user's home directory are visible
inside the Podman VM, so any bind mount ``src`` must live under ``$HOME``.
"""

from __future__ import annotations

import json
import os
import secrets
import signal
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass

# --- sensible Phase-1 limits ------------------------------------------------

DEFAULT_NETWORK = "none"
DEFAULT_TMPFS: tuple[str, ...] = ("/tmp", "/work")
DEFAULT_PIDS_LIMIT = 128
DEFAULT_MEMORY = "512m"
DEFAULT_CPUS = "1.0"
DEFAULT_COMMAND: tuple[str, ...] = ("sleep", "infinity")

_NAME_PREFIX = "artil-sbx-"


@dataclass(frozen=True)
class ExecResult:
    """Outcome of a command executed inside the sandbox."""

    returncode: int
    stdout: str
    stderr: str
    timed_out: bool

    @property
    def ok(self) -> bool:
        """True when the command finished on its own with a zero exit status."""
        return self.returncode == 0 and not self.timed_out


def unique_sandbox_name(prefix: str = _NAME_PREFIX) -> str:
    """Return a collision-unlikely container name (no external randomness dep)."""
    return f"{prefix}{time.time_ns() % 10_000_000_000}-{os.getpid()}-{secrets.token_hex(4)}"


def build_container_args(
    image: str,
    *,
    name: str,
    network: str = DEFAULT_NETWORK,
    read_only: bool = True,
    tmpfs: Sequence[str] | None = None,
    cap_drop: bool = True,
    no_new_privileges: bool = True,
    pids_limit: int | str | None = DEFAULT_PIDS_LIMIT,
    memory: str | None = DEFAULT_MEMORY,
    cpus: str | float | int | None = DEFAULT_CPUS,
    mounts: Sequence[tuple[str, str]] | None = None,
    command: Sequence[str] | None = None,
) -> list[str]:
    """Build the podman ``run`` argument list for an isolated sandbox container.

    Pure and side-effect free: it returns the list that follows the ``podman``
    binary (``run -d ... <image> <command>``). Used by :class:`Sandbox` and the
    unit tests. ``mounts`` are read-only bind mounts ``(host_src, container_dst)``.
    """

    tmpfs = DEFAULT_TMPFS if tmpfs is None else list(tmpfs)
    command = DEFAULT_COMMAND if command is None else list(command)
    mounts = list(mounts) if mounts else []

    args: list[str] = [
        "run",
        "-d",
        "--name",
        name,
        "--network",
        network,
    ]

    if read_only:
        args += ["--read-only"]
    for mount in tmpfs:
        args += ["--tmpfs", mount]
    if cap_drop:
        args += ["--cap-drop", "ALL"]
    if no_new_privileges:
        args += ["--security-opt", "no-new-privileges"]
    if pids_limit is not None:
        args += ["--pids-limit", str(pids_limit)]
    if memory is not None:
        args += ["--memory", str(memory)]
    if cpus is not None:
        args += ["--cpus", str(cpus)]
    for src, dst in mounts:
        args += ["-v", f"{src}:{dst}:ro"]

    args.append(image)
    args.extend(command)
    return args


class Sandbox:
    """Context manager wrapping one ephemeral, isolated Podman container.

    Usage::

        with Sandbox("redis:7-alpine", pids_limit=512, memory="1g") as sbx:
            r = sbx.exec(["sh", "-c", "echo hi"])

    The container is force-removed on normal exit, on any exception, and on
    KeyboardInterrupt -- never leaked.
    """

    def __init__(
        self,
        image: str,
        *,
        name: str | None = None,
        network: str = DEFAULT_NETWORK,
        read_only: bool = True,
        tmpfs: Sequence[str] | None = None,
        cap_drop: bool = True,
        no_new_privileges: bool = True,
        pids_limit: int | str | None = DEFAULT_PIDS_LIMIT,
        memory: str | None = DEFAULT_MEMORY,
        cpus: str | float | int | None = DEFAULT_CPUS,
        mounts: Sequence[tuple[str, str]] | None = None,
        podman_bin: str = "podman",
        launch_timeout: float = 120.0,
    ) -> None:
        self.podman_bin = podman_bin
        self.image = image
        self.name = name or unique_sandbox_name()
        self.network = network
        self.read_only = read_only
        self.tmpfs = tmpfs
        self.cap_drop = cap_drop
        self.no_new_privileges = no_new_privileges
        self.pids_limit = pids_limit
        self.memory = memory
        self.cpus = cpus
        self.mounts = list(mounts) if mounts else []
        self.launch_timeout = launch_timeout

        # Populated at launch / inspected:
        self.container_id: str | None = None
        self.image_id: str | None = None
        self.image_digest: str | None = None
        self._created = False

    # --- lifecycle ----------------------------------------------------------

    def __enter__(self) -> Sandbox:
        self._inspect_image()
        try:
            self._launch()
        except BaseException:
            # Never leak a half-created container.
            self._remove(suppress=True)
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        # ALWAYS tear down -- on normal exit, on exception, on KeyboardInterrupt.
        # Returning False means we never swallow the in-flight exception.
        self._remove(suppress=True)
        return False

    # --- podman calls -------------------------------------------------------

    def _inspect_image(self) -> None:
        """Resolve and record the image id / digest for reproducibility."""
        res = self._run(["image", "inspect", self.image], check=False, timeout=self.launch_timeout)
        if res.returncode != 0:
            raise RuntimeError(f"image '{self.image}' not found: {res.stderr.strip()}")
        data = json.loads(res.stdout or "[]")
        first = data[0] if isinstance(data, list) and data else {}
        self.image_id = first.get("Id", "")
        digests = first.get("RepoDigests") or []
        self.image_digest = digests[0] if digests else self.image_id

    def _launch(self) -> None:
        args = build_container_args(
            self.image,
            name=self.name,
            network=self.network,
            read_only=self.read_only,
            tmpfs=self.tmpfs,
            cap_drop=self.cap_drop,
            no_new_privileges=self.no_new_privileges,
            pids_limit=self.pids_limit,
            memory=self.memory,
            cpus=self.cpus,
            mounts=self.mounts,
        )
        res = self._run(args, check=False, timeout=self.launch_timeout)
        if res.returncode != 0:
            raise RuntimeError(f"podman run failed: {res.stderr.strip()}")
        self.container_id = (res.stdout or "").strip() or self.name
        self._created = True

    def _remove(self, *, suppress: bool) -> None:
        if not self._created:
            return
        # Stop with no grace period (SIGKILL immediately) so teardown does not
        # wait the default 10s; tolerate "not running". Then force-remove so the
        # container is *always* gone, even on exceptions.
        self._run(["stop", "--time", "0", self.name], check=False, timeout=self.launch_timeout)
        res = self._run(["rm", "-f", self.name], check=False, timeout=self.launch_timeout)
        if res.returncode == 0:
            self._created = False
            self.container_id = None
        elif not suppress:
            raise RuntimeError(f"podman rm failed: {res.stderr.strip()}")

    def _run(
        self, argv_prefix: list[str], *, check: bool, timeout: float
    ) -> subprocess.CompletedProcess:
        """Run ``podman <argv_prefix>`` and return the CompletedProcess."""
        cmd = [self.podman_bin, *argv_prefix]
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )

    # --- operations ---------------------------------------------------------

    def exec(self, cmd: Sequence[str], *, timeout: float | None = None) -> ExecResult:
        """Run ``cmd`` inside the container. Never hangs.

        On timeout the exec is killed and :class:`ExecResult` is returned with
        ``timed_out=True``.
        """
        argv = [self.podman_bin, "exec", self.name, *[str(c) for c in cmd]]
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            out, err = proc.communicate(timeout=timeout)
            return ExecResult(proc.returncode or 0, out or "", err or "", timed_out=False)
        except subprocess.TimeoutExpired:
            # Kill the whole local process group so the pipe write-ends close
            # and the reap below cannot block; orphans die when the container exits.
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            out, err = proc.communicate()
            rc = proc.returncode if proc.returncode is not None else -9
            return ExecResult(rc, out or "", err or "", timed_out=True)

    def inspect(self) -> dict:
        """Return the parsed ``podman inspect <name>`` dict for this container."""
        res = self._run(["inspect", self.name], check=False, timeout=self.launch_timeout)
        if res.returncode != 0:
            raise RuntimeError(f"podman inspect failed: {res.stderr.strip()}")
        data = json.loads(res.stdout or "[]")
        return data[0] if isinstance(data, list) and data else {}

    @property
    def is_running(self) -> bool:
        """True only if a still-live container with this name exists."""
        if not self._created:
            return False
        res = self._run(["inspect", self.name], check=False, timeout=self.launch_timeout)
        return res.returncode == 0
