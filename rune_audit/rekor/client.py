# SPDX-License-Identifier: Apache-2.0
"""Rekor transparency log client."""

from __future__ import annotations

import hashlib
from typing import Any

import httpx

from rune_audit.rekor.models import LogEntry, LogInfo, SearchResult


class RekorClient:
    """Client for the Rekor transparency log API."""

    def __init__(self, base_url: str = "https://rekor.sigstore.dev", client: httpx.Client | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._owns_client = client is None
        self._client = client or httpx.Client(base_url=self._base_url)

    def __enter__(self) -> RekorClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def search_by_hash(self, hash_val: str) -> list[str]:
        """Search for log entry UUIDs by hash."""
        url = f"{self._base_url}/api/v1/index/retrieve"
        query = {"hash": hash_val if ":" in hash_val else f"sha256:{hash_val}"}
        
        resp = self._client.post(url, json=query)
        if resp.status_code == 404:
            return []
        if not resp.is_success:
            raise RuntimeError(f"Rekor search failed: {resp.status_code}")
            
        data = resp.json()
        if isinstance(data, list):
            return data
        return []

    def search_by_email(self, email: str) -> list[str]:
        """Search for log entry UUIDs by email."""
        url = f"{self._base_url}/api/v1/index/retrieve"
        query = {"email": email}
        
        resp = self._client.post(url, json=query)
        if resp.status_code == 404:
            return []
        if not resp.is_success:
            raise RuntimeError(f"Rekor search failed: {resp.status_code}")
            
        data = resp.json()
        if isinstance(data, list):
            return data
        return []

    def get_entry(self, uuid: str) -> LogEntry:
        """Fetch a log entry by its UUID."""
        url = f"{self._base_url}/api/v1/log/entries/{uuid}"
        
        resp = self._client.get(url)
        if resp.status_code == 404:
            raise RuntimeError("not found")
        if not resp.is_success:
            raise RuntimeError(f"get_entry failed: {resp.status_code}")
            
        data = resp.json()
        if not isinstance(data, dict) or not data:
            raise RuntimeError("Unexpected response")
            
        # The key should be the UUID or similar, but the value is the dict
        # Typically data = { "uuid_str": { "body": "...", ... } }
        key = list(data.keys())[0]
        entry_data = data[key]
        
        return LogEntry(
            uuid=uuid,
            body=entry_data.get("body", ""),
            integrated_time=entry_data.get("integratedTime", 0),
            log_index=entry_data.get("logIndex", 0),
            verification=entry_data.get("verification")
        )

    def get_log_info(self) -> LogInfo:
        """Get information about the current state of the log."""
        url = f"{self._base_url}/api/v1/log"
        
        resp = self._client.get(url)
        if not resp.is_success:
            raise RuntimeError(f"get_log_info failed: {resp.status_code}")
            
        data = resp.json()
        return LogInfo(
            tree_size=data.get("treeSize", 0),
            root_hash=data.get("rootHash", ""),
            tree_id=data.get("treeID", ""),
            signed_tree_head=data.get("signedTreeHead", "")
        )

    def verify_inclusion(self, entry: LogEntry) -> bool:
        """Verify the inclusion proof of an entry."""
        if not entry.verification or "inclusionProof" not in entry.verification:
            return False
            
        proof = entry.verification["inclusionProof"]
        root_hash = proof.get("rootHash", "")
        tree_size = proof.get("treeSize", 0)
        hashes = proof.get("hashes", [])
        log_index = proof.get("logIndex", -1)
        
        if not root_hash or tree_size <= 0 or log_index < 0:
            return False
            
        current_hash = hashlib.sha256(entry.body.encode()).hexdigest()
        
        if tree_size == 1:
            return current_hash == root_hash
            
        for sibling in hashes:
            if log_index % 2 == 0:
                combined = current_hash + sibling
            else:
                combined = sibling + current_hash
            current_hash = hashlib.sha256(combined.encode()).hexdigest()
            log_index //= 2
            
        return current_hash == root_hash
