# SPDX-License-Identifier: Apache-2.0
"""CVE (Common Vulnerabilities and Exposures) scan result models.

Parses Grype and Trivy JSON output formats.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class CVESeverity(str, Enum):
    """CVE severity levels."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NEGLIGIBLE = "Negligible"
    UNKNOWN = "Unknown"


class CVEFinding(BaseModel):
    """A single CVE finding from a vulnerability scanner."""

    cve_id: str = Field(description="CVE identifier (e.g. CVE-2024-1234)")
    severity: CVESeverity = Field(default=CVESeverity.UNKNOWN, description="CVSS severity")
    cvss_score: float | None = Field(default=None, description="CVSS score (0.0-10.0)")
    package_name: str = Field(default="", description="Affected package name")
    package_version: str = Field(default="", description="Installed version")
    fixed_version: str = Field(default="", description="Fixed version (empty if no fix)")
    scanner: str = Field(default="", description="Scanner that found this (grype, trivy)")
    description: str = Field(default="", description="CVE description")


class CVEScanResult(BaseModel):
    """Aggregated CVE scan results from one or more scanners."""

    findings: list[CVEFinding] = Field(default_factory=list, description="All CVE findings")
    scanner_name: str = Field(default="", description="Primary scanner name")
    scan_timestamp: datetime | None = Field(default=None, description="When the scan ran")
    source_repo: str = Field(default="", description="Source repository")
    target: str = Field(default="", description="Scan target (image, path)")

    @classmethod
    def from_grype(cls, data: dict[str, Any], source_repo: str = "") -> CVEScanResult:
        """Parse Grype JSON output.

        Args:
            data: Parsed Grype JSON dictionary.
            source_repo: Repository the scan was run against.

        Returns:
            Parsed CVEScanResult instance.
        """
        findings: list[CVEFinding] = []
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            severity_str = vuln.get("severity", "Unknown")
            try:
                severity = CVESeverity(severity_str)
            except ValueError:
                severity = CVESeverity.UNKNOWN

            cvss_score: float | None = None
            for cvss_entry in vuln.get("cvss", []):
                metrics = cvss_entry.get("metrics", {})
                if "baseScore" in metrics:
                    cvss_score = float(metrics["baseScore"])
                    break

            fixed_versions = vuln.get("fix", {}).get("versions", [])
            fixed_version = fixed_versions[0] if fixed_versions else ""

            findings.append(
                CVEFinding(
                    cve_id=vuln.get("id", ""),
                    severity=severity,
                    cvss_score=cvss_score,
                    package_name=artifact.get("name", ""),
                    package_version=artifact.get("version", ""),
                    fixed_version=fixed_version,
                    scanner="grype",
                    description=vuln.get("description", ""),
                )
            )

        descriptor = data.get("descriptor", {})
        target = data.get("source", {}).get("target", "")
        if isinstance(target, dict):
            target = target.get("userInput", "")

        timestamp = None
        ts_str = descriptor.get("timestamp")
        if ts_str:
            timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

        return cls(
            findings=findings,
            scanner_name=f"grype {descriptor.get('version', '')}".strip(),
            scan_timestamp=timestamp,
            source_repo=source_repo,
            target=str(target),
        )

    @classmethod
    def from_trivy(cls, data: dict[str, Any], source_repo: str = "") -> CVEScanResult:
        """Parse Trivy JSON output.

        Args:
            data: Parsed Trivy JSON dictionary.
            source_repo: Repository the scan was run against.

        Returns:
            Parsed CVEScanResult instance.
        """
        findings: list[CVEFinding] = []
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                severity_str = vuln.get("Severity", "UNKNOWN").capitalize()
                try:
                    severity = CVESeverity(severity_str)
                except ValueError:
                    severity = CVESeverity.UNKNOWN

                cvss_score: float | None = None
                cvss_data = vuln.get("CVSS", {})
                for source_data in cvss_data.values():
                    if "V3Score" in source_data:
                        cvss_score = float(source_data["V3Score"])
                        break

                findings.append(
                    CVEFinding(
                        cve_id=vuln.get("VulnerabilityID", ""),
                        severity=severity,
                        cvss_score=cvss_score,
                        package_name=vuln.get("PkgName", ""),
                        package_version=vuln.get("InstalledVersion", ""),
                        fixed_version=vuln.get("FixedVersion", ""),
                        scanner="trivy",
                        description=vuln.get("Description", ""),
                    )
                )

        artifact_name = data.get("ArtifactName", "")
        timestamp = None
        ts_str = data.get("CreatedAt")
        if ts_str:
            timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

        return cls(
            findings=findings,
            scanner_name="trivy",
            scan_timestamp=timestamp,
            source_repo=source_repo,
            target=artifact_name,
        )

    def deduplicated_findings(self) -> list[CVEFinding]:
        """Return findings deduplicated by CVE ID, keeping highest severity."""
        seen: dict[str, CVEFinding] = {}
        severity_order = list(CVESeverity)
        for finding in self.findings:
            existing = seen.get(finding.cve_id)
            if existing is None:
                seen[finding.cve_id] = finding
            else:
                existing_idx = severity_order.index(existing.severity)
                new_idx = severity_order.index(finding.severity)
                if new_idx < existing_idx:
                    seen[finding.cve_id] = finding
        return list(seen.values())

    @classmethod
    def merge(cls, *scans: CVEScanResult) -> CVEScanResult:
        """Merge multiple scan results, deduplicating by CVE ID.

        Args:
            *scans: CVEScanResult instances to merge.

        Returns:
            Merged CVEScanResult with deduplicated findings.
        """
        all_findings: list[CVEFinding] = []
        source_repos: set[str] = set()
        for scan in scans:
            all_findings.extend(scan.findings)
            if scan.source_repo:
                source_repos.add(scan.source_repo)

        merged = cls(
            findings=all_findings,
            scanner_name="merged",
            source_repo=", ".join(sorted(source_repos)),
        )
        merged.findings = merged.deduplicated_findings()
        return merged
