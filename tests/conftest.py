# SPDX-License-Identifier: Apache-2.0
"""Shared pytest fixtures for rune-audit tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from rune_audit.models.evidence import EvidenceBundle
from rune_audit.models.gate import GateResult, GateStatus

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture()
def cyclonedx_data() -> dict[str, Any]:
    """Load sample CycloneDX SBOM fixture."""
    return json.loads((FIXTURES_DIR / "sample_cyclonedx.json").read_text(encoding="utf-8"))


@pytest.fixture()
def grype_data() -> dict[str, Any]:
    """Load sample Grype scan report fixture."""
    return json.loads((FIXTURES_DIR / "sample_grype.json").read_text(encoding="utf-8"))


@pytest.fixture()
def trivy_data() -> dict[str, Any]:
    """Load sample Trivy scan report fixture."""
    return json.loads((FIXTURES_DIR / "sample_trivy.json").read_text(encoding="utf-8"))


@pytest.fixture()
def openvex_data() -> dict[str, Any]:
    """Load sample OpenVEX document fixture."""
    return json.loads((FIXTURES_DIR / "sample_openvex.json").read_text(encoding="utf-8"))


@pytest.fixture()
def attestation_data() -> dict[str, Any]:
    """Load sample GitHub attestation data."""
    return json.loads((FIXTURES_DIR / "sample_attestation.json").read_text(encoding="utf-8"))


@pytest.fixture()
def sample_sbom() -> dict[str, Any]:
    """Load sample CycloneDX SBOM fixture."""
    return json.loads((FIXTURES_DIR / "sbom_cyclonedx.json").read_text(encoding="utf-8"))


@pytest.fixture()
def sample_grype_report() -> dict[str, Any]:
    """Load sample Grype scan report fixture."""
    return json.loads((FIXTURES_DIR / "grype_report.json").read_text(encoding="utf-8"))


@pytest.fixture()
def sample_trivy_report() -> dict[str, Any]:
    """Load sample Trivy scan report fixture."""
    return json.loads((FIXTURES_DIR / "trivy_report.json").read_text(encoding="utf-8"))


@pytest.fixture()
def sample_openvex() -> dict[str, Any]:
    """Load sample OpenVEX document fixture."""
    return json.loads((FIXTURES_DIR / "openvex.json").read_text(encoding="utf-8"))


@pytest.fixture()
def sample_workflow_run() -> dict[str, Any]:
    """Load sample GitHub Actions workflow run fixture."""
    return json.loads((FIXTURES_DIR / "gh_workflow_run.json").read_text(encoding="utf-8"))


@pytest.fixture()
def mock_github_api() -> respx.MockRouter:
    """Mock GitHub REST API via respx."""
    with respx.mock(base_url="https://api.github.com", assert_all_called=False) as router:
        router.route().mock(return_value=httpx.Response(404, json={"message": "Not Found"}))
        yield router


def make_gate_result(
    gate_name: str = "RuneGate/Coverage/Python",
    status: GateStatus = GateStatus.PASS,
) -> GateResult:
    """Factory function for creating test GateResult instances."""
    return GateResult(gate_name=gate_name, status=status)


def make_evidence_bundle(
    repos: list[str] | None = None,
) -> EvidenceBundle:
    """Factory function for creating test EvidenceBundle instances."""
    return EvidenceBundle(
        repos=repos or ["lpasquali/rune"],
        gate_results=[
            make_gate_result("RuneGate/Coverage/Python", GateStatus.PASS),
            make_gate_result("RuneGate/Security/SAST", GateStatus.PASS),
            make_gate_result("RuneGate/Security/SecretScanning", GateStatus.PASS),
        ],
    )


@pytest.fixture()
def evidence_bundle() -> EvidenceBundle:
    """Pre-built EvidenceBundle with sample items."""
    return make_evidence_bundle()
