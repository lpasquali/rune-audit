# SPDX-License-Identifier: Apache-2.0
"""Integration tests against a live Ollama instance (RuneGate/Ollama-Integration)."""

from __future__ import annotations

import os

import httpx
import pytest

_OLLAMA_READY = bool(os.environ.get("OLLAMA_TEST_URL") and os.environ.get("OLLAMA_TEST_MODEL"))

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _OLLAMA_READY,
        reason="OLLAMA_TEST_URL / OLLAMA_TEST_MODEL not set (local runs skip; CI sets both)",
    ),
]


@pytest.fixture()
def ollama_url() -> str:
    return os.environ["OLLAMA_TEST_URL"].rstrip("/")


@pytest.fixture()
def ollama_model() -> str:
    return os.environ["OLLAMA_TEST_MODEL"]


def test_ollama_tags_lists_model(ollama_url: str, ollama_model: str) -> None:
    """Ollama /api/tags includes the configured model after pull."""
    with httpx.Client(timeout=30.0) as client:
        r = client.get(f"{ollama_url}/api/tags")
    assert r.status_code == 200
    data = r.json()
    models = {m.get("name", "") for m in data.get("models", [])}
    # Names may be "tinyllama" or "tinyllama:latest"
    assert any(name == ollama_model or name.startswith(f"{ollama_model}:") for name in models), (
        f"model {ollama_model!r} not in {models}"
    )


def test_ollama_generate_returns_response(ollama_url: str, ollama_model: str) -> None:
    """Minimal generate call succeeds against the pulled model."""
    payload = {"model": ollama_model, "prompt": "Reply with exactly: OK", "stream": False}
    with httpx.Client(timeout=120.0) as client:
        r = client.post(f"{ollama_url}/api/generate", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("done") is True
    assert isinstance(body.get("response"), str)
    assert len(body["response"]) > 0
