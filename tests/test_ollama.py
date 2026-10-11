"""Unit tests for OllamaBackend using a local http.server that mimics Ollama.

No real Ollama is required for these; only one integration test is marked
``integration`` and skips itself when Ollama / qwen3:4b are unavailable.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from artil.backend.base import Backend, ChatResponse
from artil.backend.ollama import BackendError, OllamaBackend


# A minimal standing-in-for-Ollama server. Its POST /api/chat returns whatever
# body/status the test sets on the server; its GET /api/tags returns a model list.
class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:
        if self.path == "/api/tags":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(getattr(self.server, "tags_body", b'{"models": []}'))
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        status = getattr(self.server, "status", 200)
        if status != 200:
            self.send_error(status)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(getattr(self.server, "chat_body", b"{}"))


@pytest.fixture()
def ollama():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    server.status = 200
    server.chat_body = b"{}"
    server.tags_body = b'{"models": []}'
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _, port = server.server_address
    backend = OllamaBackend(host=f"http://127.0.0.1:{port}", model="qwen3:4b", timeout=5.0)
    try:
        yield backend, server
    finally:
        server.shutdown()
        server.server_close()


def test_chat_parses_tool_call_with_dict_arguments(ollama):
    backend, server = ollama
    server.chat_body = json.dumps(
        {
            "message": {
                "content": "calling",
                "tool_calls": [
                    {"function": {"name": "read_file", "arguments": {"path": "/etc/hostname"}}}
                ],
            },
            "eval_count": 3,
            "total_ns": 10_000,
        }
    ).encode()
    resp = backend.chat([{"role": "user", "content": "hi"}], tools=[])
    assert isinstance(resp, ChatResponse)
    assert resp.content == "calling"
    assert resp.tool_calls[0].name == "read_file"
    assert resp.tool_calls[0].arguments == {"path": "/etc/hostname"}


def test_chat_coerces_json_string_arguments_to_dict(ollama):
    backend, server = ollama
    server.chat_body = json.dumps(
        {
            "message": {
                "content": "",
                "tool_calls": [
                    {"function": {"name": "run_shell", "arguments": '{"command": "ls"}'}}
                ],
            },
            "eval_count": 1,
            "total_ns": 7_000,
        }
    ).encode()
    resp = backend.chat([{"role": "user", "content": "hi"}], tools=[])
    assert resp.tool_calls[0].arguments == {"command": "ls"}


def test_chat_with_no_tool_calls_is_a_final_answer(ollama):
    backend, server = ollama
    server.chat_body = json.dumps(
        {"message": {"content": "done here"}, "eval_count": 5, "total_ns": 4_000}
    ).encode()
    resp = backend.chat([{"role": "user", "content": "hi"}], tools=[])
    assert resp.tool_calls == []
    assert resp.content == "done here"


def test_chat_missing_eval_count_defaults_to_zero(ollama):
    backend, server = ollama
    server.chat_body = json.dumps({"message": {"content": "x"}}).encode()
    resp = backend.chat([], tools=[])
    assert resp.eval_count == 0 and resp.total_ns == 0


def test_chat_http_500_raises_backend_error(ollama):
    backend, server = ollama
    server.status = 500
    server.chat_body = b"server is on fire"
    with pytest.raises(BackendError, match="500"):
        backend.chat([{"role": "user", "content": "hi"}], tools=[])


def test_chat_malformed_json_raises_backend_error(ollama):
    backend, server = ollama
    server.chat_body = b"this is not json {"
    with pytest.raises(BackendError, match="cannot decode"):
        backend.chat([{"role": "user", "content": "hi"}], tools=[])


def test_chat_connection_refused_raises_backend_error():
    backend = OllamaBackend(host="http://127.0.0.1:1", model="qwen3:4b", timeout=2.0)
    with pytest.raises(BackendError, match="connection failed"):
        backend.chat([{"role": "user", "content": "hi"}], tools=[])


def test_model_digest_reads_from_tags(ollama):
    backend, server = ollama
    server.tags_body = json.dumps(
        {
            "models": [
                {"name": "some:old", "digest": "sha256:old"},
                {"name": "qwen3:4b", "digest": "sha256:new-123"},
            ]
        }
    ).encode()
    assert backend.model_digest() == "sha256:new-123"


def test_model_digest_missing_raises(ollama):
    backend, _ = ollama  # tags_body is {"models": []}
    with pytest.raises(BackendError, match="not found"):
        backend.model_digest()


def test_ollama_backend_is_a_backend():
    backend = OllamaBackend(host="http://127.0.0.1:1", model="qwen3:4b", timeout=1.0)
    assert isinstance(backend, Backend)


@pytest.mark.integration
def test_integration_real_ollama_if_present():
    # Only run with a real, reachable Ollama that has qwen3:4b; else skip.
    from artil.doctor import DEFAULT_OLLAMA_URL, get_ollama_models, model_is_present

    try:
        models = get_ollama_models(DEFAULT_OLLAMA_URL, timeout=4.0)
    except Exception:
        pytest.skip("Ollama not reachable; skipping the live Ollama test")
    if not model_is_present(models, "qwen3:4b"):
        pytest.skip("qwen3:4b not available; skipping the live Ollama test")
    backend = OllamaBackend(host=DEFAULT_OLLAMA_URL, model="qwen3:4b", timeout=60.0)
    resp = backend.chat([{"role": "user", "content": "Say the single word 'pong'."}], tools=[])
    assert isinstance(resp, ChatResponse)
    assert resp.content != ""


PYEOF = 0
