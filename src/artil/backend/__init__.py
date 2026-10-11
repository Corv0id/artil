"""LLM backend layer.

Defines a swappable `Backend` interface (Ollama in Phase 1, with
OpenAI-compatible vLLM/llama.cpp/cloud later) so the attacker, victim,
judge, and embedder roles can use different models behind one API.
"""

from artil.backend.base import (
    Backend,
    BackendError,
    ChatResponse,
    Message,
    ToolCall,
)
from artil.backend.ollama import (
    DEFAULT_HOST,
    DEFAULT_NUM_CTX,
    DEFAULT_TEMPERATURE,
    DEFAULT_THINK,
    OllamaBackend,
)

__all__ = [
    "Backend",
    "BackendError",
    "ChatResponse",
    "Message",
    "ToolCall",
    "OllamaBackend",
    "DEFAULT_HOST",
    "DEFAULT_NUM_CTX",
    "DEFAULT_TEMPERATURE",
    "DEFAULT_THINK",
]
