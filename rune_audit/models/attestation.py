"""TPM2 attestation result models (stub).

Full implementation tracked in future issues.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class AttestationResult(BaseModel):
    """Result of a TPM2 attestation check (stub)."""

    device_id: str = Field(default="", description="Device identifier")
    verified: bool = Field(default=False, description="Whether attestation passed")
    message: str = Field(default="", description="Human-readable result message")
