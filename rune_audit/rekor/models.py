# SPDX-License-Identifier: Apache-2.0
"""Pydantic models for Rekor transparency log entries."""

from __future__ import annotations

from pydantic import BaseModel, Field


class LogEntry(BaseModel):
    """A single entry in the Rekor transparency log."""

    uuid: str = Field(description="Unique identifier for the log entry")
    body: str = Field(description="Base64-encoded entry body")
    integrated_time: int = Field(description="Unix timestamp when entry was integrated")
    log_index: int = Field(description="Index in the transparency log")
    verification: dict | None = Field(  # type: ignore[type-arg]
        default=None, description="Verification data including inclusion proof"
    )


class LogInfo(BaseModel):
    """Information about the Rekor transparency log."""

    tree_size: int = Field(description="Number of entries in the log")
    root_hash: str = Field(description="Root hash of the Merkle tree")
    tree_id: str = Field(description="Unique identifier for the log tree")
    signed_tree_head: str = Field(description="Signed tree head (checkpoint)")


class SearchResult(BaseModel):
    """Result of a Rekor index search."""

    uuids: list[str] = Field(default_factory=list, description="Matching entry UUIDs")
