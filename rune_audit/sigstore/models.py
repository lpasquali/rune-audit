# SPDX-License-Identifier: Apache-2.0
"""Models for Sigstore operations."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from datetime import datetime


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
