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
    message: str = "Coverage 98%",
) -> GateResult:
    """Factory function for creating test GateResult instances."""
    return GateResult(gate_name=gate_name, status=status, message=message)


def make_evidence_bundle(
    repos: list[str] | None = None,
) -> EvidenceBundle:
    """Factory function for creating test EvidenceBundle instances."""
    return EvidenceBundle(
        repos=repos or ["lpasquali/rune"],
        gate_results=[
            make_gate_result("RuneGate/Coverage/Python", GateStatus.PASS, "97%"),
            make_gate_result("RuneGate/Security/SAST", GateStatus.PASS, "No findings"),
            make_gate_result("RuneGate/Security/SecretScanning", GateStatus.PASS, "Clean"),
        ],
    )


@pytest.fixture()
def evidence_bundle() -> EvidenceBundle:
    """Pre-built EvidenceBundle with sample items."""
    return make_evidence_bundle()
