"""Shared fixtures for verifier tests."""

from __future__ import annotations

import pytest

from rune_audit.verifiers.slsa import AttestationBundle


@pytest.fixture()
def passing_bundle() -> AttestationBundle:
    return AttestationBundle(
        repo="rune",
        tag="v0.0.0a2",
        found=True,
        payload={
            "predicate": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "builder": {"id": "https://github.com/actions/runner"},
                "invocation": {"configSource": {"digest": {"sha1": "abc123def456"}}},
                "metadata": {"buildFinishedOn": "2026-04-01T12:00:00Z"},
                "materials": [{"digest": {"sha1": "abc123def456"}}],
            }
        },
    )


@pytest.fixture()
def missing_bundle() -> AttestationBundle:
    return AttestationBundle(repo="rune", tag="v0.0.0a2", found=False, error="No attestation found")


@pytest.fixture()
def slsa_v1_bundle() -> AttestationBundle:
    return AttestationBundle(
        repo="rune-operator",
        tag="v0.0.0a2",
        found=True,
        payload={
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                    "resolvedDependencies": [{"uri": "x", "digest": {"gitCommit": "deadbeef1234"}}],
                },
                "runDetails": {"builder": {"id": "https://github.com/actions/runner/github-hosted"}},
            }
        },
    )


@pytest.fixture()
def gh_verify_bundle() -> AttestationBundle:
    return AttestationBundle(
        repo="rune-ui",
        tag="v0.0.0a2",
        found=True,
        payload=[
            {
                "verificationResult": {
                    "statement": {
                        "predicate": {
                            "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                            "builder": {"id": "https://github.com/slsa-framework/slsa-github-generator"},
                            "invocation": {"configSource": {"digest": {"sha1": "cafebabe0000"}}},
                            "metadata": {"buildFinishedOn": "2026-04-01T14:00:00Z"},
                        }
                    }
                }
            }
        ],
    )
