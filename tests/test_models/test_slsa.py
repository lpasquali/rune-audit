"""Tests for SLSA attestation data models."""

from __future__ import annotations

import base64
import json
from typing import Any

from rune_audit.models.slsa import SLSAAttestation


def test_slsa_attestation_defaults() -> None:
    """SLSAAttestation has sensible defaults."""
    att = SLSAAttestation()
    assert att.subject_digest == ""
    assert att.subject_name == ""
    assert att.builder_id == ""
    assert att.build_type == ""
    assert att.build_timestamp is None
    assert att.verified is False


def test_slsa_attestation_from_github_attestation() -> None:
    """from_github_attestation parses a GitHub API attestation entry."""
    statement = {
        "subject": [
            {
                "name": "ghcr.io/lpasquali/rune",
                "digest": {"sha256": "abcdef123456"},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/lpasquali/rune",
                        "digest": {"gitCommit": "deadbeef"},
                    }
                ],
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/actions/runner",
                },
                "metadata": {
                    "buildStartedOn": "2026-04-01T12:00:00Z",
                },
            },
        },
    }
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    data: dict[str, Any] = {
        "bundle": {
            "dsseEnvelope": {
                "payload": payload,
                "payloadType": "application/vnd.in-toto+json",
            }
        },
        "repositoryId": 12345,
    }
    att = SLSAAttestation.from_github_attestation(data, source_repo="lpasquali/rune")
    assert att.subject_name == "ghcr.io/lpasquali/rune"
    assert att.subject_digest == "abcdef123456"
    assert att.builder_id == "https://github.com/actions/runner"
    assert att.build_type == "https://actions.github.io/buildtypes/workflow/v1"
    assert att.source_repo == "lpasquali/rune"
    assert att.source_ref == "deadbeef"
    assert att.build_timestamp is not None


def test_slsa_attestation_from_github_empty() -> None:
    """from_github_attestation handles empty/missing data."""
    att = SLSAAttestation.from_github_attestation({})
    assert att.subject_digest == ""
    assert att.builder_id == ""
    assert att.build_timestamp is None


def test_slsa_attestation_from_github_bad_payload() -> None:
    """from_github_attestation handles invalid base64 payload."""
    data: dict[str, Any] = {
        "bundle": {
            "dsseEnvelope": {
                "payload": "not-valid-base64!!!",
            }
        },
    }
    att = SLSAAttestation.from_github_attestation(data)
    assert att.subject_digest == ""


def test_slsa_attestation_from_github_no_subjects() -> None:
    """from_github_attestation handles statement with no subjects."""
    statement: dict[str, Any] = {"subject": [], "predicate": {}}
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    data: dict[str, Any] = {
        "bundle": {"dsseEnvelope": {"payload": payload}},
    }
    att = SLSAAttestation.from_github_attestation(data)
    assert att.subject_digest == ""
    assert att.subject_name == ""


def test_slsa_attestation_from_github_empty_payload() -> None:
    """from_github_attestation handles empty payload string."""
    data: dict[str, Any] = {"bundle": {"dsseEnvelope": {"payload": ""}}}
    att = SLSAAttestation.from_github_attestation(data)
    assert att.subject_digest == ""
