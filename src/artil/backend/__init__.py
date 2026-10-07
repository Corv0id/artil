"""LLM backend layer.

Defines a swappable `Backend` interface (Ollama in Phase 1, with
OpenAI-compatible vLLM/llama.cpp/cloud later) so the attacker, victim,
judge, and embedder roles can use different models behind one API.
"""
