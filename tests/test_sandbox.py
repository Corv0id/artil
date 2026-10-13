"""Tests for artil.infra.sandbox.

Two tiers:

    * Unit tests (no podman): arg construction, name gen, ExecResult dataclass.
    * Integration (pytest.mark.integration): require podman CLI+VM+image;
      auto-skip when unavailable so the suite stays green in a bare env.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import FrozenInstanceError

import pytest

from artil.infra.sandbox import (
    DEFAULT_MEMORY,
    DEFAULT_PIDS_LIMIT,
    DEFAULT_TMPFS,
    ExecResult,
    Sandbox,
    build_container_args,
    unique_sandbox_name,
)

PODMAN = shutil.which("podman")

ROOTFS_WRITE = (
    "echo data > /rootonly.txt 2>/dev/null; ( test -f /rootonly.txt && echo yes ) || echo no"
)
TMP_WRITE = "echo data > /tmp/tmp.txt && cat /tmp/tmp.txt"


# --- Pure unit tests (no podman needed) ------------------------------------


def test_build_args_defaults_have_deny_everything_posture():
    args = build_container_args("image:tag", name="c1")
    assert args[:3] == ["run", "-d", "--name"]
    assert "c1" in args
    assert args.count("--network") == 1 and "none" in args
    assert "--read-only" in args
    assert "--tmpfs" in args
    assert "/tmp" in args and "/work" in args
    assert "--cap-drop" in args and "ALL" in args
    assert "--security-opt" in args
    assert "no-new-privileges" in args
    assert str(DEFAULT_PIDS_LIMIT) in args
    assert DEFAULT_MEMORY in args
    assert args[-2:] == ["sleep", "infinity"]


def test_build_args_custom_network_and_command():
    args = build_container_args("foo:bar", name="c2", network="bridge", command=["/bin/sh"])
    assert "bridge" in args
    assert args[-1] == "/bin/sh"
    assert "infinity" not in args


def test_build_args_optional_flags_can_be_disabled():
    args = build_container_args(
        "img",
        name="c3",
        read_only=False,
        cap_drop=False,
        no_new_privileges=False,
        pids_limit=None,
        memory=None,
        cpus=None,
    )
    assert "--read-only" not in args
    assert "--cap-drop" not in args
    assert "--security-opt" not in args
    assert "--pids-limit" not in args
    assert "--memory" not in args
    assert "--cpus" not in args


def test_build_args_read_only_bind_mounts_use_ro():
    args = build_container_args(
        "img",
        name="c4",
        mounts=[("/home/u/data", "/data"), ("/home/u/cfg", "/cfg")],
    )
    assert "-v" in args
    assert "/home/u/data:/data:ro" in args
    assert "/home/u/cfg:/cfg:ro" in args


def test_build_args_only_configured_limits_present():
    args = build_container_args("img", name="c5", pids_limit=7, memory="256m", cpus="0.5")
    assert "7" in args
    assert "256m" in args
    assert "0.5" in args


def test_unique_sandbox_names_differ():
    names = {unique_sandbox_name() for _ in range(1000)}
    assert len(names) == 1000
    assert all(n.startswith("artil-sbx-") for n in names)


def test_execresult_fields_and_ok_property():
    assert ExecResult(0, "x", "", False).ok is True
    assert ExecResult(1, "", "", False).ok is False
    assert ExecResult(0, "", "", True).ok is False  # timed out => not ok
    with pytest.raises(FrozenInstanceError):
        r = ExecResult(0, "", "", False)
        r.returncode = 5  # frozen -> immutable


def test_sandbox_defaults_match_architecture():
    sx = Sandbox("img", name="c6")
    assert sx.network == "none"
    assert DEFAULT_TMPFS == ("/tmp", "/work")
    assert sx._created is False


# --- Helpers for integration tests -----------------------------------------


def _require_podman() -> None:
    if PODMAN is None:
        pytest.skip("podman CLI not available")
    if not _machine_running() and not _try_start_machine():
        pytest.skip("podman machine not running and could not be started")


def _machine_running() -> bool:
    res = subprocess.run(
        [PODMAN, "machine", "list", "--format", "json"],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        return False
    try:
        machines = json.loads(res.stdout or "[]")
    except json.JSONDecodeError:
        return False
    return any(m.get("Running") for m in (machines or []))


def _try_start_machine() -> bool:
    res = subprocess.run([PODMAN, "machine", "start"], capture_output=True, text=True, timeout=180)
    return res.returncode == 0


def _select_image() -> str | None:
    env = os.environ.get("ARTIL_TEST_IMAGE")
    candidates = ([env] if env else []) + ["alpine:3"]
    for cand in candidates:
        res = subprocess.run([PODMAN, "image", "exists", cand], capture_output=True)
        if res.returncode == 0:
            return cand
    return None


def _image_available() -> str:
    """Return a usable image, or skip the test."""
    _require_podman()
    image = _select_image()
    if image is None:
        pytest.skip("no podman image available locally (set ARTIL_TEST_IMAGE)")
    return image


def _container_exists(name: str) -> bool:
    res = subprocess.run(
        [PODMAN, "ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
    )
    return any(line.strip() == name for line in res.stdout.splitlines() if line.strip())


@pytest.fixture()
def image() -> str:
    return _image_available()


# --- Integration tests -------------------------------------------------------


@pytest.mark.integration
def test_echo_works(image):
    with Sandbox(image, name="atil-test-echo") as sbx:
        r = sbx.exec(["sh", "-c", "echo hello-artil"])
        assert r.returncode == 0, r.stderr
        assert "hello-artil" in r.stdout
        assert r.ok is True
        assert sbx.image_id  # image digest resolved for reproducibility


@pytest.mark.integration
def test_external_ip_unreachable(image):
    # --network=none => no egress. busybox wget ships in alpine-based images;
    # skip cleanly if the chosen image lacks it.
    with Sandbox(image, name="atil-test-net") as sbx:
        has_wget = sbx.exec(["sh", "-c", "command -v wget"], timeout=10).ok
        if not has_wget:
            pytest.skip(f"{image} lacks wget; cannot probe external reachability")
        r = sbx.exec(
            ["wget", "-q", "-T", "3", "-O", "/dev/null", "http://1.1.1.1"],
            timeout=15,
        )
        assert r.returncode != 0, "container unexpectedly reached an external IP"
        assert not r.ok


@pytest.mark.integration
def test_rootfs_readonly_but_tmpfs_writable(image):
    with Sandbox(image, name="atil-test-fs") as sbx:
        r_root = sbx.exec(["sh", "-c", ROOTFS_WRITE])
        assert r_root.returncode == 0, r_root.stderr
        assert "no" in r_root.stdout, "rootfs was writable"

        r_tmp = sbx.exec(["sh", "-c", TMP_WRITE])
        assert r_tmp.returncode == 0, r_tmp.stderr
        assert "data" in r_tmp.stdout


@pytest.mark.integration
def test_inspect_shows_hardening_and_limits(image):
    pids = 256
    mem = "64m"
    with Sandbox(image, name="atil-test-inspect", pids_limit=pids, memory=mem) as sbx:
        host = sbx.inspect()["HostConfig"]
        assert host["NetworkMode"] == "none"
        assert host["ReadonlyRootfs"] is True
        assert host["PidsLimit"] == pids
        assert host["Memory"] == 64 * 1024 * 1024


@pytest.mark.integration
def test_container_removed_after_normal_exit(image):
    name = "atil-test-gone-normal"
    with Sandbox(image, name=name) as sbx:
        assert sbx.is_running is True
    assert sbx.is_running is False
    res = subprocess.run([PODMAN, "inspect", name], capture_output=True, text=True)
    assert res.returncode != 0, "container still exists after normal exit"


@pytest.mark.integration
def test_container_removed_after_exception(image):
    name = "atil-test-gone-exc"
    with pytest.raises(RuntimeError):
        with Sandbox(image, name=name) as sbx:
            assert sbx.is_running is True
            raise RuntimeError("boom inside sandbox")
    # The block exited via exception; podman rm -f must still have run.
    assert not _container_exists(name), "container leaked after exception"


@pytest.mark.integration
def test_command_timeout_returns_timed_out(image):
    with Sandbox(image, name="atil-test-timeout") as sbx:
        start = time.monotonic()
        r = sbx.exec(["sleep", "30"], timeout=2)
        elapsed = time.monotonic() - start
        assert r.timed_out is True
        assert not r.ok
        assert elapsed < 15, f"exec did not return promptly ({elapsed:.1f}s)"
        assert sbx.is_running is True  # still alive inside the block
    assert sbx.is_running is False
    assert not _container_exists("atil-test-timeout")


def _read_file(sbx: Sandbox, path: str) -> str:
    """Read a container file back via a positional-arg cat (never interpolated)."""
    res = sbx.exec(["sh", "-c", 'cat -- "$1"', "_", path])
    assert res.returncode == 0, res.stderr
    return res.stdout


@pytest.mark.integration
def test_write_file_then_read_back(image):
    content = "hello world\nsecond line\n"
    with Sandbox(image, name="atil-test-write") as sbx:
        sbx.write_file("/tmp/plain.txt", content)
        assert _read_file(sbx, "/tmp/plain.txt") == content


@pytest.mark.integration
def test_write_file_name_with_spaces_and_quotes(image):
    # spaces AND a double quote: must not be interpolated; it is a positional arg.
    weird_path = '/tmp/weird  name".txt'
    content = 'value with "quotes" and spaces\n'
    with Sandbox(image, name="atil-test-weird") as sbx:
        sbx.write_file(weird_path, content)
        assert _read_file(sbx, weird_path) == content
        listing = sbx.exec(["sh", "-c", "ls /tmp"]).stdout
        assert "weird" in listing  # the real name exists, un-mangled


@pytest.mark.integration
def test_write_file_to_readonly_rootfs_raises(image):
    # /etc is on the --read-only rootfs; only /tmp and /work (tmpfs) are writable.
    with Sandbox(image, name="atil-test-ro") as sbx:
        with pytest.raises(RuntimeError):
            sbx.write_file("/etc/cannot-write.txt", "nope")


@pytest.mark.integration
def test_write_file_treats_content_as_data_not_shell(image):
    # Shell metacharacters in content must be written literally, not executed.
    payload = "echo $HOME\nrm -rf /\n$(x)\n"
    with Sandbox(image, name="atil-test-metachar") as sbx:
        sbx.write_file("/tmp/metachar.txt", payload)
        assert _read_file(sbx, "/tmp/metachar.txt") == payload
