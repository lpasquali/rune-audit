# SPDX-License-Identifier: Apache-2.0
"""Tests for the Rekor transparency log client."""

from __future__ import annotations

import hashlib

import httpx
import pytest
import respx
from rune_audit.rekor.client import RekorClient
from rune_audit.rekor.models import LogEntry, LogInfo, SearchResult

REKOR_BASE = "https://rekor.sigstore.dev"


class TestLogEntryModel:
    """Tests for LogEntry model."""

    def test_create(self) -> None:
        entry = LogEntry(
            uuid="abc123",
            body="dGVzdA==",
            integrated_time=1700000000,
            log_index=42,
        )
        assert entry.uuid == "abc123"
        assert entry.verification is None

    def test_with_verification(self) -> None:
        entry = LogEntry(
            uuid="abc",
            body="body",
            integrated_time=0,
            log_index=0,
            verification={"inclusionProof": {"rootHash": "abc"}},
        )
        assert entry.verification is not None

    def test_serialization(self) -> None:
        entry = LogEntry(uuid="x", body="y", integrated_time=1, log_index=2)
        data = entry.model_dump()
        restored = LogEntry.model_validate(data)
        assert restored == entry


class TestLogInfoModel:
    """Tests for LogInfo model."""

    def test_create(self) -> None:
        info = LogInfo(
            tree_size=1000,
            root_hash="abcdef",
            tree_id="tree-1",
            signed_tree_head="sth-data",
        )
        assert info.tree_size == 1000

    def test_serialization(self) -> None:
        info = LogInfo(
            tree_size=5, root_hash="h", tree_id="t", signed_tree_head="s"
        )
        data = info.model_dump()
        restored = LogInfo.model_validate(data)
        assert restored == info


class TestSearchResultModel:
    """Tests for SearchResult model."""

    def test_create_empty(self) -> None:
        sr = SearchResult()
        assert sr.uuids == []

    def test_create_with_uuids(self) -> None:
        sr = SearchResult(uuids=["a", "b", "c"])
        assert len(sr.uuids) == 3


class TestRekorClientSearchByHash:
    """Tests for RekorClient.search_by_hash()."""

    @respx.mock
    def test_search_found(self) -> None:
        respx.post(f"{REKOR_BASE}/api/v1/index/retrieve").mock(
            return_value=httpx.Response(200, json=["uuid1", "uuid2"])
        )
        with RekorClient() as client:
            result = client.search_by_hash("abcdef1234567890")
        assert result == ["uuid1", "uuid2"]

    @respx.mock
    def test_search_not_found(self) -> None:
        respx.post(f"{REKOR_BASE}/api/v1/index/retrieve").mock(
            return_value=httpx.Response(404)
        )
        with RekorClient() as client:
            result = client.search_by_hash("nonexistent")
        assert result == []

    @respx.mock
    def test_search_server_error(self) -> None:
        respx.post(f"{REKOR_BASE}/api/v1/index/retrieve").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )
        with RekorClient() as client, pytest.raises(RuntimeError, match="Rekor search failed: 500"):
            client.search_by_hash("hash")

    @respx.mock
    def test_search_non_list_response(self) -> None:
        respx.post(f"{REKOR_BASE}/api/v1/index/retrieve").mock(
            return_value=httpx.Response(200, json={"error": "unexpected"})
        )
        with RekorClient() as client:
            result = client.search_by_hash("hash")
        assert result == []


class TestRekorClientSearchByEmail:
    """Tests for RekorClient.search_by_email()."""

    @respx.mock
    def test_search_found(self) -> None:
        respx.post(f"{REKOR_BASE}/api/v1/index/retrieve").mock(
            return_value=httpx.Response(200, json=["uuid3"])
        )
        with RekorClient() as client:
            result = client.search_by_email("user@example.com")
        assert result == ["uuid3"]

    @respx.mock
    def test_search_not_found(self) -> None:
        respx.post(f"{REKOR_BASE}/api/v1/index/retrieve").mock(
            return_value=httpx.Response(404)
        )
        with RekorClient() as client:
            result = client.search_by_email("nobody@example.com")
        assert result == []

    @respx.mock
    def test_search_error(self) -> None:
        respx.post(f"{REKOR_BASE}/api/v1/index/retrieve").mock(
            return_value=httpx.Response(503, text="Service Unavailable")
        )
        with RekorClient() as client, pytest.raises(RuntimeError, match="Rekor search failed: 503"):
            client.search_by_email("user@example.com")

    @respx.mock
    def test_search_non_list_response(self) -> None:
        respx.post(f"{REKOR_BASE}/api/v1/index/retrieve").mock(
            return_value=httpx.Response(200, json="not-a-list")
        )
        with RekorClient() as client:
            result = client.search_by_email("user@example.com")
        assert result == []


class TestRekorClientGetEntry:
    """Tests for RekorClient.get_entry()."""

    @respx.mock
    def test_get_entry_success(self) -> None:
        entry_data = {
            "abc123": {
                "body": "dGVzdA==",
                "integratedTime": 1700000000,
                "logIndex": 42,
                "verification": {
                    "inclusionProof": {
                        "rootHash": "deadbeef",
                        "logIndex": 42,
                        "treeSize": 100,
                        "hashes": ["h1", "h2"],
                    }
                },
            }
        }
        respx.get(f"{REKOR_BASE}/api/v1/log/entries/abc123").mock(
            return_value=httpx.Response(200, json=entry_data)
        )
        with RekorClient() as client:
            entry = client.get_entry("abc123")
        assert entry.uuid == "abc123"
        assert entry.body == "dGVzdA=="
        assert entry.integrated_time == 1700000000
        assert entry.log_index == 42
        assert entry.verification is not None

    @respx.mock
    def test_get_entry_not_found(self) -> None:
        respx.get(f"{REKOR_BASE}/api/v1/log/entries/missing").mock(
            return_value=httpx.Response(404)
        )
        with RekorClient() as client, pytest.raises(RuntimeError, match="not found"):
            client.get_entry("missing")

    @respx.mock
    def test_get_entry_server_error(self) -> None:
        respx.get(f"{REKOR_BASE}/api/v1/log/entries/err").mock(
            return_value=httpx.Response(500, text="error")
        )
        with RekorClient() as client, pytest.raises(RuntimeError, match="get_entry failed: 500"):
            client.get_entry("err")

    @respx.mock
    def test_get_entry_unexpected_format(self) -> None:
        respx.get(f"{REKOR_BASE}/api/v1/log/entries/bad").mock(
            return_value=httpx.Response(200, json=[])
        )
        with RekorClient() as client, pytest.raises(RuntimeError, match="Unexpected response"):
            client.get_entry("bad")

    @respx.mock
    def test_get_entry_empty_dict(self) -> None:
        respx.get(f"{REKOR_BASE}/api/v1/log/entries/empty").mock(
            return_value=httpx.Response(200, json={})
        )
        with RekorClient() as client, pytest.raises(RuntimeError, match="Unexpected response"):
            client.get_entry("empty")


class TestRekorClientGetLogInfo:
    """Tests for RekorClient.get_log_info()."""

    @respx.mock
    def test_get_log_info_success(self) -> None:
        respx.get(f"{REKOR_BASE}/api/v1/log").mock(
            return_value=httpx.Response(
                200,
                json={
                    "treeSize": 50000,
                    "rootHash": "aabbccdd",
                    "treeID": "tree-123",
                    "signedTreeHead": "sth-encoded",
                },
            )
        )
        with RekorClient() as client:
            info = client.get_log_info()
        assert info.tree_size == 50000
        assert info.root_hash == "aabbccdd"
        assert info.tree_id == "tree-123"
        assert info.signed_tree_head == "sth-encoded"

    @respx.mock
    def test_get_log_info_error(self) -> None:
        respx.get(f"{REKOR_BASE}/api/v1/log").mock(
            return_value=httpx.Response(500, text="down")
        )
        with RekorClient() as client, pytest.raises(RuntimeError, match="get_log_info failed"):
            client.get_log_info()

    @respx.mock
    def test_get_log_info_missing_fields(self) -> None:
        """Missing fields default to zero/empty values."""
        respx.get(f"{REKOR_BASE}/api/v1/log").mock(
            return_value=httpx.Response(200, json={})
        )
        with RekorClient() as client:
            info = client.get_log_info()
        assert info.tree_size == 0
        assert info.root_hash == ""


class TestRekorClientVerifyInclusion:
    """Tests for RekorClient.verify_inclusion()."""

    def test_no_verification_data(self) -> None:
        entry = LogEntry(uuid="a", body="b", integrated_time=0, log_index=0)
        client = RekorClient()
        assert client.verify_inclusion(entry) is False
        client.close()

    def test_no_inclusion_proof(self) -> None:
        entry = LogEntry(
            uuid="a",
            body="b",
            integrated_time=0,
            log_index=0,
            verification={"signedEntryTimestamp": "abc"},
        )
        client = RekorClient()
        assert client.verify_inclusion(entry) is False
        client.close()

    def test_missing_required_fields(self) -> None:
        entry = LogEntry(
            uuid="a",
            body="b",
            integrated_time=0,
            log_index=0,
            verification={
                "inclusionProof": {
                    "rootHash": "",
                    "logIndex": -1,
                    "treeSize": 0,
                    "hashes": [],
                }
            },
        )
        client = RekorClient()
        assert client.verify_inclusion(entry) is False
        client.close()

    def test_single_node_tree_valid(self) -> None:
        """Single-node tree: body hash matches root hash."""
        body = "test-body"
        body_hash = hashlib.sha256(body.encode()).hexdigest()
        entry = LogEntry(
            uuid="a",
            body=body,
            integrated_time=0,
            log_index=0,
            verification={
                "inclusionProof": {
                    "rootHash": body_hash,
                    "logIndex": 0,
                    "treeSize": 1,
                    "hashes": [],
                }
            },
        )
        client = RekorClient()
        assert client.verify_inclusion(entry) is True
        client.close()

    def test_single_node_tree_invalid(self) -> None:
        entry = LogEntry(
            uuid="a",
            body="data",
            integrated_time=0,
            log_index=0,
            verification={
                "inclusionProof": {
                    "rootHash": "wrong_hash",
                    "logIndex": 0,
                    "treeSize": 1,
                    "hashes": [],
                }
            },
        )
        client = RekorClient()
        assert client.verify_inclusion(entry) is False
        client.close()

    def test_merkle_proof_valid(self) -> None:
        """Multi-node tree: Merkle proof chain computes to correct root hash."""
        body = "leaf-data"
        leaf_hash = hashlib.sha256(body.encode()).hexdigest()
        sibling = "sibling_hash"
        # index 0 (even): combined = leaf_hash + sibling
        combined = leaf_hash + sibling
        expected_root = hashlib.sha256(combined.encode()).hexdigest()

        entry = LogEntry(
            uuid="a",
            body=body,
            integrated_time=0,
            log_index=0,
            verification={
                "inclusionProof": {
                    "rootHash": expected_root,
                    "logIndex": 0,
                    "treeSize": 2,
                    "hashes": [sibling],
                }
            },
        )
        client = RekorClient()
        assert client.verify_inclusion(entry) is True
        client.close()

    def test_merkle_proof_odd_index(self) -> None:
        """Multi-node tree with odd index: combined = sibling + leaf_hash."""
        body = "leaf-data-odd"
        leaf_hash = hashlib.sha256(body.encode()).hexdigest()
        sibling = "left_sibling"
        # index 1 (odd): combined = sibling + leaf_hash
        combined = sibling + leaf_hash
        expected_root = hashlib.sha256(combined.encode()).hexdigest()

        entry = LogEntry(
            uuid="b",
            body=body,
            integrated_time=0,
            log_index=1,
            verification={
                "inclusionProof": {
                    "rootHash": expected_root,
                    "logIndex": 1,
                    "treeSize": 2,
                    "hashes": [sibling],
                }
            },
        )
        client = RekorClient()
        assert client.verify_inclusion(entry) is True
        client.close()

    def test_merkle_proof_invalid(self) -> None:
        entry = LogEntry(
            uuid="c",
            body="data",
            integrated_time=0,
            log_index=0,
            verification={
                "inclusionProof": {
                    "rootHash": "definitely_wrong",
                    "logIndex": 0,
                    "treeSize": 2,
                    "hashes": ["sibling"],
                }
            },
        )
        client = RekorClient()
        assert client.verify_inclusion(entry) is False
        client.close()


class TestRekorClientLifecycle:
    """Tests for RekorClient lifecycle management."""

    def test_custom_client(self) -> None:
        custom = httpx.Client(base_url=REKOR_BASE)
        client = RekorClient(client=custom)
        assert client._owns_client is False
        client.close()
        # Custom client should NOT be closed by RekorClient

    def test_context_manager(self) -> None:
        with RekorClient() as client:
            assert client._owns_client is True

    def test_custom_base_url(self) -> None:
        client = RekorClient(base_url="https://custom.rekor.dev/")
        assert client._base_url == "https://custom.rekor.dev"
        client.close()
