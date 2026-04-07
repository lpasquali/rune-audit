# SPDX-License-Identifier: Apache-2.0
"""Tests for TPM2 attestation result models."""

from rune_audit.models.attestation import AttestationResult


def test_create_passed():
    r = AttestationResult(passed=True, pcr_digest="abc", message="OK")
    assert r.passed is True and r.pcr_digest == "abc"


def test_create_failed():
    r = AttestationResult(passed=False, message="PCR mismatch")
    assert r.passed is False and r.pcr_digest == ""


def test_serialization():
    r = AttestationResult(passed=True, pcr_digest="xyz", message="v")
    assert AttestationResult.model_validate(r.model_dump()) == r


def test_defaults():
    r = AttestationResult(passed=False)
    assert r.pcr_digest == "" and r.message == ""
