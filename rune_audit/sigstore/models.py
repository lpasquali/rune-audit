# SPDX-License-Identifier: Apache-2.0
"""Models for Sigstore operations."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SigningResult(BaseModel):
    """Result of a signing operation."""

    signature: str | None = None
    certificate: str | None = None
    timestamp: datetime | None = None
    log_index: int | None = None
    bundle_path: str | None = None
    errors: list[str] = Field(default_factory=list)


class VerificationResult(BaseModel):
    """Result of a verification operation."""

    verified: bool
    signer_identity: str | None = None
    issuer: str | None = None
    log_entry: dict[str, Any] | None = None
    errors: list[str] = Field(default_factory=list)
