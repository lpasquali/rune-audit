# SPDX-License-Identifier: Apache-2.0
"""Cover Sigstore / Rekor Pydantic models (included in package coverage gate)."""

from __future__ import annotations

from rune_audit.models.sigstore import (
    RekorEntry,
    SigningResult,
    SigstoreSignature,
    VerificationResult,
)


def test_sigstore_signature_roundtrip() -> None:
    s = SigstoreSignature(signature="abc", cert="-----BEGIN", integrated_time=1, log_index=2)
    assert s.log_index == 2


def test_rekor_entry_minimal() -> None:
    e = RekorEntry(uuid="u", log_index=0, integrated_time=3, body={"k": "v"})
    assert e.body["k"] == "v"


def test_signing_result_defaults() -> None:
    ok = SigningResult()
    assert ok.success is True
    assert ok.signature is None
    assert ok.errors == []


def test_verification_result_with_errors() -> None:
    v = VerificationResult(verified=False, errors=["bad"])
    assert not v.verified
    assert v.signer_identity is None
