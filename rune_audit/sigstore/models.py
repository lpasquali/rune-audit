# SPDX-License-Identifier: Apache-2.0
"""Pydantic models for Sigstore signing and verification results."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class SigningResult(BaseModel):
    """Result of a cosign signing operation."""

    signature: str = Field(description="Base64-encoded signature")
    certificate: str = Field(description="PEM-encoded signing certificate")
    log_index: int | None = Field(default=None, description="Rekor transparency log index")
    timestamp: datetime = Field(description="Time the artifact was signed")
    bundle_path: str | None = Field(default=None, description="Path to the cosign bundle file")


class VerificationResult(BaseModel):
    """Result of a cosign verification operation."""

    verified: bool = Field(description="Whether verification succeeded")
    signer_identity: str | None = Field(default=None, description="Identity of the signer (email/URI)")
    issuer: str | None = Field(default=None, description="OIDC issuer URL")
    log_entry: dict | None = Field(default=None, description="Rekor log entry details")  # type: ignore[type-arg]
    errors: list[str] = Field(default_factory=list, description="Verification error messages")
