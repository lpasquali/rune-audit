# SPDX-License-Identifier: Apache-2.0
"""Sigstore and Rekor model definitions."""
from __future__ import annotations

from pydantic import BaseModel, Field


class SigstoreSignature(BaseModel):
    """Metadata for a Sigstore signature entry."""
    signature: str = Field(..., description="Base64 encoded signature")
    cert: str = Field(..., description="PEM encoded certificate")
    integrated_time: int = Field(..., description="Rekor integration timestamp")
    log_index: int | None = Field(default=None, description="Rekor log index")


class RekorEntry(BaseModel):
    """Transparency log entry details."""
    uuid: str = Field(..., description="Unique identifier for the log entry")
    log_index: int = Field(..., description="Log index")
    integrated_time: int = Field(..., description="Unix timestamp when entry was integrated")
    body: dict = Field(..., description="Rekor entry body")


class SigningResult(BaseModel):
    """Unified result of a signing operation."""
    success: bool = True
    signature: SigstoreSignature | None = None
    errors: list[str] = Field(default_factory=list)


class VerificationResult(BaseModel):
    """Result of a verification operation."""
    verified: bool = Field(..., description="Whether verification succeeded")
    signer_identity: str | None = Field(default=None, description="Identity of the signer")
    issuer: str | None = Field(default=None, description="OIDC issuer URL")
    log_entry: dict | None = Field(default=None, description="Rekor log entry details")
    errors: list[str] = Field(default_factory=list, description="Verification error messages")
