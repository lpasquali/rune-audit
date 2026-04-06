"""TPM2 attestation result models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AttestationResult(BaseModel):
    """Result from TPM2 attestation verification."""

    passed: bool = Field(description="Whether attestation passed")
    pcr_digest: str = Field(default="", description="PCR digest value")
    message: str = Field(default="", description="Human-readable result message")
