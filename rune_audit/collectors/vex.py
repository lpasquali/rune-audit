"""VEX document collector.

Fetches OpenVEX documents from RUNE repositories via the GitHub Contents API.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

import httpx

from rune_audit.models.vex import VEXDocument

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"
VEX_FILE_PATH = ".vex/permanent.openvex.json"


class VEXCollector:
    """Collect OpenVEX documents from GitHub repositories."""

    def __init__(
        self,
        repos: list[str] | None = None,
        token: str = "",
        client: httpx.Client | None = None,
        vex_path: str = VEX_FILE_PATH,
    ) -> None:
        self.repos = repos or []
        self._token = token
        self.vex_path = vex_path
        self._client = client or httpx.Client(
            base_url=GITHUB_API_BASE,
            headers=self._build_headers(),
            timeout=30.0,
        )
        self._owns_client = client is None

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> VEXCollector:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def fetch_vex(self, repo: str, ref: str = "main") -> VEXDocument | None:
        resp = self._client.get(
            f"/repos/{repo}/contents/{self.vex_path}",
            params={"ref": ref},
        )
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            return None
        content_data = resp.json()
        return self._parse_content_response(content_data, repo)

    def _parse_content_response(self, content_data: dict[str, Any], repo: str) -> VEXDocument | None:
        encoding = content_data.get("encoding", "")
        content = content_data.get("content", "")
        if encoding == "base64" and content:
            try:
                raw = base64.b64decode(content)
                data = json.loads(raw)
            except (ValueError, json.JSONDecodeError):
                return None
        else:
            return None
        try:
            return VEXDocument.from_openvex(data, source_repo=repo)
        except (ValueError, KeyError):
            return None

    def collect_all(self) -> list[VEXDocument]:
        documents: list[VEXDocument] = []
        for repo in self.repos:
            doc = self.fetch_vex(repo)
            if doc:
                documents.append(doc)
        return documents
