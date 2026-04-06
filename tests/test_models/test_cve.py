"""Tests for CVE scan result models."""

from __future__ import annotations

from typing import Any

from rune_audit.models.cve import CVEFinding, CVEScanResult, CVESeverity


def test_cve_severity_values() -> None:
    """CVESeverity enum has expected values."""
    assert CVESeverity.CRITICAL.value == "Critical"
    assert CVESeverity.HIGH.value == "High"
    assert CVESeverity.UNKNOWN.value == "Unknown"


def test_cve_finding_creation() -> None:
    """CVEFinding can be created with all fields."""
    finding = CVEFinding(
        cve_id="CVE-2024-0001",
        severity=CVESeverity.HIGH,
        cvss_score=7.5,
        package_name="sample-pkg",
        package_version="1.2.3",
        fixed_version="1.2.4",
        scanner="grype",
    )
    assert finding.cve_id == "CVE-2024-0001"
    assert finding.severity == CVESeverity.HIGH
    assert finding.cvss_score == 7.5


def test_cve_finding_defaults() -> None:
    """CVEFinding defaults are sensible."""
    finding = CVEFinding(cve_id="CVE-2024-0001")
    assert finding.severity == CVESeverity.UNKNOWN
    assert finding.cvss_score is None
    assert finding.package_name == ""
    assert finding.fixed_version == ""
    assert finding.scanner == ""


def test_cve_scan_result_from_grype(sample_grype_report: dict[str, Any]) -> None:
    """CVEScanResult.from_grype parses Grype JSON correctly."""
    result = CVEScanResult.from_grype(sample_grype_report, source_repo="lpasquali/rune")
    assert len(result.findings) == 2
    assert result.findings[0].cve_id == "CVE-2024-0001"
    assert result.findings[0].severity == CVESeverity.HIGH
    assert result.findings[0].cvss_score == 7.5
    assert result.findings[0].fixed_version == "1.2.4"
    assert result.findings[1].cve_id == "CVE-2024-0002"
    assert result.findings[1].fixed_version == ""
    assert result.scanner_name.startswith("grype")
    assert result.source_repo == "lpasquali/rune"
    assert result.target == "ghcr.io/lpasquali/rune:test"
    assert result.scan_timestamp is not None


def test_cve_scan_result_from_trivy(sample_trivy_report: dict[str, Any]) -> None:
    """CVEScanResult.from_trivy parses Trivy JSON correctly."""
    result = CVEScanResult.from_trivy(sample_trivy_report, source_repo="lpasquali/rune")
    assert len(result.findings) == 2
    assert result.findings[0].cve_id == "CVE-2024-0001"
    assert result.findings[0].severity == CVESeverity.HIGH
    assert result.findings[1].cve_id == "CVE-2024-0003"
    assert result.target == "ghcr.io/lpasquali/rune:test"
    assert result.scan_timestamp is not None


def test_cve_scan_result_from_grype_empty() -> None:
    """CVEScanResult.from_grype handles empty matches."""
    result = CVEScanResult.from_grype({"matches": [], "descriptor": {}, "source": {}})
    assert len(result.findings) == 0


def test_cve_scan_result_from_trivy_empty() -> None:
    """CVEScanResult.from_trivy handles empty results."""
    result = CVEScanResult.from_trivy({"Results": []})
    assert len(result.findings) == 0


def test_cve_scan_result_deduplicated(
    sample_grype_report: dict[str, Any],
    sample_trivy_report: dict[str, Any],
) -> None:
    """Deduplicated findings remove duplicates by CVE ID."""
    grype = CVEScanResult.from_grype(sample_grype_report)
    trivy = CVEScanResult.from_trivy(sample_trivy_report)
    merged = CVEScanResult.merge(grype, trivy)
    deduped = merged.deduplicated_findings()
    cve_ids = [f.cve_id for f in deduped]
    assert cve_ids.count("CVE-2024-0001") == 1
    assert "CVE-2024-0002" in cve_ids
    assert "CVE-2024-0003" in cve_ids


def test_cve_scan_result_merge_source_repos() -> None:
    """Merge combines source repos."""
    a = CVEScanResult(findings=[], scanner_name="grype", source_repo="repo-a")
    b = CVEScanResult(findings=[], scanner_name="trivy", source_repo="repo-b")
    merged = CVEScanResult.merge(a, b)
    assert "repo-a" in merged.source_repo
    assert "repo-b" in merged.source_repo


def test_cve_scan_result_from_grype_unknown_severity() -> None:
    """Grype parser handles unknown severity gracefully."""
    data: dict[str, Any] = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-9999-0001",
                    "severity": "SuperCritical",
                    "cvss": [],
                    "fix": {"state": "unknown", "versions": []},
                },
                "artifact": {"name": "pkg", "version": "1.0"},
            }
        ],
        "descriptor": {},
        "source": {},
    }
    result = CVEScanResult.from_grype(data)
    assert result.findings[0].severity == CVESeverity.UNKNOWN
    assert result.findings[0].cvss_score is None


def test_cve_scan_result_from_trivy_unknown_severity() -> None:
    """Trivy parser handles unknown severity gracefully."""
    data: dict[str, Any] = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-9999-0002",
                        "Severity": "BANANAS",
                        "PkgName": "pkg",
                        "InstalledVersion": "1.0",
                    }
                ]
            }
        ],
    }
    result = CVEScanResult.from_trivy(data)
    assert result.findings[0].severity == CVESeverity.UNKNOWN


def test_cve_scan_result_from_grype_target_string() -> None:
    """Grype parser handles target as a plain string."""
    data: dict[str, Any] = {
        "matches": [],
        "descriptor": {},
        "source": {"target": "dir:/some/path"},
    }
    result = CVEScanResult.from_grype(data)
    assert result.target == "dir:/some/path"


def test_cve_scan_result_from_grype_no_cvss() -> None:
    """Grype parser handles missing CVSS data."""
    data: dict[str, Any] = {
        "matches": [
            {
                "vulnerability": {"id": "CVE-X", "severity": "High"},
                "artifact": {"name": "pkg", "version": "1.0"},
            }
        ],
    }
    result = CVEScanResult.from_grype(data)
    assert result.findings[0].cvss_score is None
