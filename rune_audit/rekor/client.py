# SPDX-License-Identifier: Apache-2.0
"""Rekor transparency log client."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from rune_audit.models.sigstore import RekorEntry

if TYPE_CHECKING:
    from typing import Final


class RekorClient:
    """Client for the Rekor transparency log API."""

    def __init__(self, url: str = "https://rekor.sigstore.dev") -> None:
        self.url = url.rstrip("/")

    def get_entry_by_index(self, index: int) -> RekorEntry | None:
        """Fetch a log entry by its index."""
        url = f"{self.url}/api/v1/log/entries?logIndex={index}"
        try:
            resp = httpx.get(url, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            if not data:
                return None
            uuid = list(data.keys())[0]
            entry_data = data[uuid]
            
            return RekorEntry(
                uuid=uuid,
                log_index=entry_data.get("logIndex", index),
                integrated_time=entry_data.get("integratedTime", 0),
                body=entry_data.get("body", {})
            )
        except (httpx.HTTPError, ValueError, KeyError, IndexError):
            return None

    def get_entry_by_uuid(self, uuid: str) -> RekorEntry | None:
        """Fetch a log entry by its UUID."""
        url = f"{self.url}/api/v1/log/entries/{uuid}"
        try:
            resp = httpx.get(url, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            if not data:
                return None
            entry_data = data.get(uuid, data)
            
            return RekorEntry(
                uuid=uuid,
                log_index=entry_data.get("logIndex", 0),
                integrated_time=entry_data.get("integratedTime", 0),
                body=entry_data.get("body", {})
            )
        except (httpx.HTTPError, ValueError, KeyError):
            return None

    def search(self, hash_value: str | None = None, email: str | None = None) -> list[str]:
        """Search for log entry UUIDs."""
        url = f"{self.url}/api/v1/index/retrieve"
        query: dict[str, Any] = {}
        if hash_value:
            query["hash"] = hash_value if ":" in hash_value else f"sha256:{hash_value}"
        if email:
            query["email"] = email
            
        if not query:
            return []

        try:
            resp = httpx.post(url, json=query, timeout=10.0)
            resp.raise_for_status()
            return list(resp.json())
        except (httpx.HTTPError, ValueError):
            return []
