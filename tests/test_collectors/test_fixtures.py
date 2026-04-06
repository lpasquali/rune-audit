"""Tests verifying test fixtures load correctly."""

from __future__ import annotations

from typing import Any

import httpx
import respx


def test_sbom_fixture_structure(sample_sbom: dict[str, Any]) -> None:
    """SBOM fixture has expected CycloneDX structure."""
    assert sample_sbom["bomFormat"] == "CycloneDX"
    assert "components" in sample_sbom
    assert len(sample_sbom["components"]) > 0


def test_grype_fixture_structure(sample_grype_report: dict[str, Any]) -> None:
    """Grype fixture has expected structure."""
    assert "matches" in sample_grype_report
    assert len(sample_grype_report["matches"]) > 0


def test_trivy_fixture_structure(sample_trivy_report: dict[str, Any]) -> None:
    """Trivy fixture has expected structure."""
    assert "Results" in sample_trivy_report
    assert len(sample_trivy_report["Results"]) > 0


def test_openvex_fixture_structure(sample_openvex: dict[str, Any]) -> None:
    """OpenVEX fixture has expected structure."""
    assert "@context" in sample_openvex
    assert "statements" in sample_openvex
    assert sample_openvex["version"] == 1


def test_workflow_run_fixture_structure(sample_workflow_run: dict[str, Any]) -> None:
    """Workflow run fixture has expected structure."""
    assert sample_workflow_run["status"] == "completed"
    assert sample_workflow_run["conclusion"] == "success"
    assert "repository" in sample_workflow_run


def test_mock_github_api_default_404(mock_github_api: respx.MockRouter) -> None:
    """Mock GitHub API returns 404 for unregistered routes."""
    response = httpx.get("https://api.github.com/repos/test/test")
    assert response.status_code == 404


def test_mock_github_api_custom_route() -> None:
    """Mock GitHub API can register custom responses via respx."""
    with respx.mock(base_url="https://api.github.com") as router:
        router.get("/repos/lpasquali/rune/actions/runs").mock(
            return_value=httpx.Response(200, json={"workflow_runs": []})
        )
        response = httpx.get("https://api.github.com/repos/lpasquali/rune/actions/runs")
        assert response.status_code == 200
        assert response.json() == {"workflow_runs": []}
