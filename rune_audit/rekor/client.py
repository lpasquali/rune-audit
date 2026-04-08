# SPDX-License-Identifier: Apache-2.0
"""HTTP client for the Rekor transparency log API."""

from __future__ import annotations

import hashlib

import httpx

from rune_audit.rekor.models import LogEntry, LogInfo


class RekorClient:
    """Client for interacting with the Rekor transparency log REST API.

    Args:
        base_url: Base URL of the Rekor instance.
        client: Optional pre-configured httpx.Client for testing.
    """

    def __init__(
        self,
        base_url: str = "https://rekor.sigstore.dev",
        client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(base_url=self._base_url, timeout=30.0)
        self._owns_client = client is None

    def close(self) -> None:
        """Close the underlying HTTP client if we own it."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> RekorClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def search_by_hash(self, sha256: str) -> list[str]:
        """Search for log entries by SHA-256 hash.

        Args:
            sha256: Hex-encoded SHA-256 hash of the artifact.

        Returns:
            List of matching entry UUIDs.

        Raises:
            RuntimeError: If the API returns an error.
        """
        resp = self._client.post(
            "/api/v1/index/retrieve",
            json={"hash": f"sha256:{sha256}"},
        )
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            raise RuntimeError(f"Rekor search failed: {resp.status_code} {resp.text}")
        data = resp.json()
        if isinstance(data, list):
            return [str(u) for u in data]
        return []

    def search_by_email(self, email: str) -> list[str]:
        """Search for log entries by signer email.

        Args:
            email: Email address of the signer.

        Returns:
            List of matching entry UUIDs.

        Raises:
            RuntimeError: If the API returns an error.
        """
        resp = self._client.post(
            "/api/v1/index/retrieve",
            json={"email": email},
        )
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            raise RuntimeError(f"Rekor search failed: {resp.status_code} {resp.text}")
        data = resp.json()
        if isinstance(data, list):
            return [str(u) for u in data]
        return []

    def get_entry(self, uuid: str) -> LogEntry:
        """Retrieve a specific log entry by UUID.

        Args:
            uuid: The entry UUID.

        Returns:
            The log entry.

        Raises:
            RuntimeError: If the entry is not found or the API returns an error.
        """
        resp = self._client.get(f"/api/v1/log/entries/{uuid}")
        if resp.status_code == 404:
            raise RuntimeError(f"Rekor entry not found: {uuid}")
        if resp.status_code != 200:
            raise RuntimeError(f"Rekor get_entry failed: {resp.status_code} {resp.text}")

        data = resp.json()
        # Response is a dict of {uuid: entry_data}
        if isinstance(data, dict):
            for entry_uuid, entry_data in data.items():
                return LogEntry(
                    uuid=str(entry_uuid),
                    body=entry_data.get("body", ""),
                    integrated_time=entry_data.get("integratedTime", 0),
                    log_index=entry_data.get("logIndex", 0),
                    verification=entry_data.get("verification"),
                )
        raise RuntimeError(f"Unexpected response format for entry {uuid}")

    def get_log_info(self) -> LogInfo:
        """Get transparency log metadata.

        Returns:
            Log information including tree size and root hash.

        Raises:
            RuntimeError: If the API returns an error.
        """
        resp = self._client.get("/api/v1/log")
        if resp.status_code != 200:
            raise RuntimeError(f"Rekor get_log_info failed: {resp.status_code} {resp.text}")

        data = resp.json()
        return LogInfo(
            tree_size=data.get("treeSize", 0),
            root_hash=data.get("rootHash", ""),
            tree_id=data.get("treeID", ""),
            signed_tree_head=data.get("signedTreeHead", ""),
        )

    def verify_inclusion(self, entry: LogEntry) -> bool:
        """Verify that an entry is included in the transparency log.

        Performs a local Merkle inclusion proof verification by checking that
        the entry body hash is consistent with the provided inclusion proof.

        Args:
            entry: The log entry to verify.

        Returns:
            True if the inclusion proof is valid.
        """
        if entry.verification is None:
            return False

        inclusion_proof = entry.verification.get("inclusionProof")
        if inclusion_proof is None:
            return False

        # Verify the proof has required fields
        root_hash = inclusion_proof.get("rootHash", "")
        log_index = inclusion_proof.get("logIndex", -1)
        tree_size = inclusion_proof.get("treeSize", 0)
        hashes = inclusion_proof.get("hashes", [])

        if not root_hash or log_index < 0 or tree_size <= 0:
            return False

        if not hashes:
            # Single-node tree: body hash should match root hash
            body_hash = hashlib.sha256(entry.body.encode()).hexdigest()
            return body_hash == root_hash

        # Verify Merkle proof chain
        leaf_hash = hashlib.sha256(entry.body.encode()).hexdigest()
        computed = leaf_hash
        index = log_index

        for h in hashes:
            combined = computed + h if index % 2 == 0 else h + computed
            computed = hashlib.sha256(combined.encode()).hexdigest()
            index //= 2

        return computed == root_hash
