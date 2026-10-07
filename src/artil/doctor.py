"""Environment health checks for `artil doctor`.

Each check prints one clear line and reports a boolean. `run_doctor`
aggregates them and returns a process exit code (0 = all passed).

The checks depend only on the standard library. External calls are injected
as callables so the checks are unit-testable without a live environment.
"""

from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_VICTIM_MODEL = "qwen3:4b"
DEFAULT_PODMAN_BIN = "podman"
DEFAULT_TIMEOUT = 10.0


@dataclass(frozen=True)
class CheckResult:
    """Outcome of a single environment check."""

    name: str
    passed: bool
    detail: str

    def line(self) -> str:
        mark = "PASS" if self.passed else "FAIL"
        return f"[{mark}] {self.name}: {self.detail}"


def http_get_json(url: str, timeout: float = DEFAULT_TIMEOUT):
    """GET *url* and decode the JSON body. Raises on any failure."""
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
        raw = resp.read()
    return json.loads(raw.decode("utf-8"))


def get_ollama_models(base_url: str, timeout: float, json_get=http_get_json):
    """Return the list of model dicts advertised by Ollama."""
    data = json_get(f"{base_url.rstrip('/')}/api/tags", timeout)
    if isinstance(data, dict):
        return data.get("models", [])
    if isinstance(data, list):
        return data
    raise TypeError(f"unexpected /api/tags payload: {type(data).__name__}")


def model_is_present(models, target: str) -> bool:
    """True if *target* matches an advertised model name (with/without tag)."""
    base = target.split(":", 1)[0]
    for model in models:
        name = model.get("name", "") if isinstance(model, dict) else str(model)
        if not name:
            continue
        if name == target or name == f"{target}:latest":
            return True
        if name.startswith(target + ":") or name.split(":", 1)[0] == base:
            return True
    return False


def check_ollama_reachable(
    base_url: str = DEFAULT_OLLAMA_URL,
    timeout: float = DEFAULT_TIMEOUT,
    json_get=http_get_json,
    models_get=get_ollama_models,
) -> tuple[CheckResult, list[dict]]:
    """Check that Ollama is reachable; also returns the model list to reuse."""
    try:
        models = models_get(base_url, timeout, json_get)
    except urllib.error.URLError as exc:
        return (
            CheckResult("ollama", False, f"not reachable at {base_url} ({exc.reason})"),
            [],
        )
    except (OSError, TypeError, json.JSONDecodeError) as exc:
        return (
            CheckResult("ollama", False, f"bad /api/tags response at {base_url} ({exc})"),
            [],
        )
    return (
        CheckResult("ollama", True, f"reachable at {base_url} ({len(models)} model(s))"),
        models,
    )


def check_model_present(
    models: list[dict],
    target: str = DEFAULT_VICTIM_MODEL,
) -> CheckResult:
    """Check that a specific model is advertised by Ollama."""
    if model_is_present(models, target):
        return CheckResult("model", True, f"'{target}' is present")
    return CheckResult(
        "model",
        False,
        f"'{target}' not found (run: ollama pull {target})",
    )


def check_podman_running(
    podman_bin: str = DEFAULT_PODMAN_BIN,
    runner=subprocess.run,
    timeout: float = DEFAULT_TIMEOUT,
) -> CheckResult:
    """Check that a Podman machine is running (parse `podman machine list`)."""
    try:
        proc = runner(
            [podman_bin, "machine", "list", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return CheckResult("podman", False, f"'{podman_bin}' not found on PATH")
    except subprocess.TimeoutExpired:
        return CheckResult("podman", False, "timed out querying podman machine list")

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "unknown error").strip().splitlines()
        detail = detail[-1] if detail else f"exit {proc.returncode}"
        return CheckResult("podman", False, f"podman machine list failed: {detail}")

    try:
        machines = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return CheckResult("podman", False, "could not parse podman machine list output")

    if not isinstance(machines, list):
        return CheckResult("podman", False, "unexpected podman machine list output")
    running = [m.get("Name", "?") for m in machines if m.get("Running")]
    if running:
        return CheckResult("podman", True, f"machine(s) running: {', '.join(running)}")
    return CheckResult("podman", False, "no running machine (run: podman machine start)")


def run_doctor(
    out,
    *,
    base_url: str = DEFAULT_OLLAMA_URL,
    model: str = DEFAULT_VICTIM_MODEL,
    podman_bin: str = DEFAULT_PODMAN_BIN,
    timeout: float = DEFAULT_TIMEOUT,
    runner=subprocess.run,
    json_get=http_get_json,
    models_get=get_ollama_models,
) -> int:
    """Run every check, print one line each, return a non-zero exit code on failure."""
    ollama, models = check_ollama_reachable(base_url, timeout, json_get, models_get)
    results = [ollama]
    results.append(check_model_present(models, model))
    results.append(check_podman_running(podman_bin, runner, timeout))

    for result in results:
        out.write(result.line() + "\n")

    failed = [r for r in results if not r.passed]
    if failed:
        out.write(f"{len(failed)} of {len(results)} check(s) failed\n")
        return 1
    out.write(f"all {len(results)} check(s) passed\n")
    return 0
