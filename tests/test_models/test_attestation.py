"""Tests for TPM2 attestation result models."""

from __future__ import annotations

from rune_audit.models.attestation import AttestationResult


def test_attestation_result_defaults() -> None:
    """AttestationResult has sensible defaults."""
    result = AttestationResult()
    assert result.device_id == ""
    assert result.verified is False
    assert result.message == ""


def test_attestation_result_creation() -> None:
    """AttestationResult can be created with all fields."""
    result = AttestationResult(
        device_id="tpm-001",
        verified=True,
        message="Attestation verified",
    )
    assert result.device_id == "tpm-001"
    assert result.verified is True
