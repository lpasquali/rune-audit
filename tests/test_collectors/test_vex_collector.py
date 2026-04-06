"""Tests for VEX document collector."""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx

from rune_audit.collectors.vex import VEXCollector


def _make_vex_content_response(vex_data: dict[str, Any]) -> dict[str, Any]:
    content = base64.b64encode(json.dumps(vex_data).encode()).decode()
    return {"content": content, "encoding": "base64"}


class TestVEXCollector:
    def _make_collector(self, responses: dict[str, tuple[int, Any]]) -> VEXCollector:
        resp_map = responses
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            for key, (status, body) in resp_map.items():
                if key in path:
                    return httpx.Response(status, json=body)
            return httpx.Response(404, json={"message": "Not Found"})
        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport, base_url="https://api.github.com")
        return VEXCollector(repos=["lpasquali/rune", "lpasquali/rune-docs"], token="test", client=client)

    def test_fetch_vex(self) -> None:
        vex_data = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "test", "author": "test", "timestamp": "2026-04-01T00:00:00Z", "version": 1, "statements": [{"vulnerability": {"name": "CVE-X"}, "status": "not_affected", "justification": "component_not_present", "impact_statement": "N/A"}]}
        collector = self._make_collector({"/repos/lpasquali/rune/contents/": (200, _make_vex_content_response(vex_data))})
        doc = collector.fetch_vex("lpasquali/rune")
        assert doc is not None
        assert doc.author == "test"
        collector.close()

    def test_fetch_vex_not_found(self) -> None:
        collector = self._make_collector({})
        assert collector.fetch_vex("lpasquali/rune") is None
        collector.close()

    def test_fetch_vex_api_error(self) -> None:
        collector = self._make_collector({"/repos/lpasquali/rune/contents/": (500, {"message": "error"})})
        assert collector.fetch_vex("lpasquali/rune") is None
        collector.close()

    def test_fetch_vex_invalid_encoding(self) -> None:
        collector = self._make_collector({"/repos/lpasquali/rune/contents/": (200, {"content": "test", "encoding": "utf-8"})})
        assert collector.fetch_vex("lpasquali/rune") is None
        collector.close()

    def test_fetch_vex_invalid_json(self) -> None:
        content = base64.b64encode(b"not json").decode()
        collector = self._make_collector({"/repos/lpasquali/rune/contents/": (200, {"content": content, "encoding": "base64"})})
        assert collector.fetch_vex("lpasquali/rune") is None
        collector.close()

    def test_fetch_vex_invalid_openvex(self) -> None:
        content = base64.b64encode(json.dumps({"invalid": "data"}).encode()).decode()
        collector = self._make_collector({"/repos/lpasquali/rune/contents/": (200, {"content": content, "encoding": "base64"})})
        assert collector.fetch_vex("lpasquali/rune") is None
        collector.close()

    def test_collect_all(self) -> None:
        vex_data = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "test", "author": "test", "timestamp": "2026-04-01T00:00:00Z", "version": 1, "statements": []}
        collector = self._make_collector({"/repos/lpasquali/rune/contents/": (200, _make_vex_content_response(vex_data)), "/repos/lpasquali/rune-docs/contents/": (200, _make_vex_content_response(vex_data))})
        docs = collector.collect_all()
        assert len(docs) == 2
        collector.close()

    def test_context_manager(self) -> None:
        transport = httpx.MockTransport(lambda r: httpx.Response(404))
        client = httpx.Client(transport=transport, base_url="https://api.github.com")
        with VEXCollector(repos=[], token="t", client=client) as c:
            assert c is not None


class TestVEXCollectorEdgeCases:
    def test_collector_default_init(self) -> None:
        """Test init without client (owns_client=True)."""
        # Just verify the constructor works, then close
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {"GITHUB_TOKEN": "", "RUNE_AUDIT_GITHUB_TOKEN": ""}):
            c = VEXCollector(repos=["lpasquali/rune"], token="tok")
            assert c._owns_client is True
            c.close()

    def test_collector_headers_with_token(self) -> None:
        """Ensure headers include Authorization when token is set."""
        c = VEXCollector(repos=[], token="my-token")
        headers = c._build_headers()
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer my-token"
        c.close()

    def test_collector_headers_without_token(self) -> None:
        """Ensure headers omit Authorization when no token."""
        c = VEXCollector(repos=[], token="")
        headers = c._build_headers()
        assert "Authorization" not in headers
        c.close()
