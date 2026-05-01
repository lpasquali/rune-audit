# SPDX-License-Identifier: Apache-2.0
"""Models for Rekor client."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class LogEntry(BaseModel):
    """Transparency log entry."""

    uuid: str
    body: str
    integrated_time: int
    log_index: int
    verification: dict[str, Any] | None = None


class LogInfo(BaseModel):
    """Transparency log information."""

    tree_size: int = 0
    root_hash: str = ""
    tree_id: str = ""
    signed_tree_head: str = ""


class SearchResult(BaseModel):
    """Search result from Rekor."""

    uuids: list[str] = Field(default_factory=list)
