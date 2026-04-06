"""VEX document validator.

Validates OpenVEX documents for structural correctness, cross-references
VEX suppressions against CVE scan results, and evaluates justification
strength for IEC 62443 ML4 DM-4 compliance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from rune_audit.models.cve import CVEFinding, CVEScanResult
from rune_audit.models.vex import VEXDocument, VEXJustification, VEXStatement, VEXStatus


class ValidationSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationFinding:
    severity: ValidationSeverity
    message: str
    cve_id: str = ""
    source_repo: str = ""


@dataclass
class VEXValidationResult:
    findings: list[ValidationFinding] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return any(f.severity == ValidationSeverity.ERROR for f in self.findings)

    @property
    def has_warnings(self) -> bool:
        return any(f.severity == ValidationSeverity.WARNING for f in self.findings)

    @property
    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == ValidationSeverity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == ValidationSeverity.WARNING)


class VEXValidator:
    def validate_document(self, doc: VEXDocument) -> VEXValidationResult:
        result = VEXValidationResult()
        for stmt in doc.statements:
            self._validate_statement(stmt, doc.source_repo, result)
        return result

    def _validate_statement(self, stmt: VEXStatement, source_repo: str, result: VEXValidationResult) -> None:
        cve_id = stmt.vulnerability_name
        if stmt.status == VEXStatus.NOT_AFFECTED and stmt.justification is None:
            result.findings.append(ValidationFinding(
                severity=ValidationSeverity.ERROR,
                message="not_affected status requires justification",
                cve_id=cve_id, source_repo=source_repo,
            ))
        if stmt.status == VEXStatus.AFFECTED and not stmt.action_statement:
            result.findings.append(ValidationFinding(
                severity=ValidationSeverity.WARNING,
                message="affected status should include action_statement",
                cve_id=cve_id, source_repo=source_repo,
            ))
        if not stmt.impact_statement:
            result.findings.append(ValidationFinding(
                severity=ValidationSeverity.WARNING,
                message="missing impact_statement",
                cve_id=cve_id, source_repo=source_repo,
            ))
        self._validate_justification_strength(stmt, source_repo, result)

    def _validate_justification_strength(
        self, stmt: VEXStatement, source_repo: str, result: VEXValidationResult,
    ) -> None:
        if stmt.status != VEXStatus.NOT_AFFECTED or stmt.justification is None:
            return
        cve_id = stmt.vulnerability_name
        if stmt.justification == VEXJustification.VULNERABLE_CODE_NOT_PRESENT:
            if not stmt.impact_statement:
                result.findings.append(ValidationFinding(
                    severity=ValidationSeverity.WARNING,
                    message="vulnerable_code_not_present justification should cite version evidence",
                    cve_id=cve_id, source_repo=source_repo,
                ))
        elif stmt.justification == VEXJustification.COMPONENT_NOT_PRESENT:
            if not stmt.impact_statement:
                result.findings.append(ValidationFinding(
                    severity=ValidationSeverity.WARNING,
                    message="component_not_present justification should cite build config evidence",
                    cve_id=cve_id, source_repo=source_repo,
                ))
        elif stmt.justification == VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY:
            if not stmt.impact_statement:
                result.findings.append(ValidationFinding(
                    severity=ValidationSeverity.WARNING,
                    message="vulnerable_code_cannot_be_controlled_by_adversary justification should cite mitigation",
                    cve_id=cve_id, source_repo=source_repo,
                ))

    def cross_check(self, vex_docs: list[VEXDocument], scan_results: list[CVEScanResult]) -> VEXValidationResult:
        result = VEXValidationResult()
        all_vex_cves: dict[str, VEXStatement] = {}
        for doc in vex_docs:
            for stmt in doc.statements:
                all_vex_cves[stmt.vulnerability_name] = stmt
        all_scan_findings: dict[str, CVEFinding] = {}
        for scan in scan_results:
            for finding in scan.findings:
                if finding.cve_id not in all_scan_findings:
                    all_scan_findings[finding.cve_id] = finding
        for cve_id, stmt in all_vex_cves.items():
            if stmt.status == VEXStatus.NOT_AFFECTED:
                scan_finding = all_scan_findings.get(cve_id)
                if scan_finding and scan_finding.fixed_version:
                    result.findings.append(ValidationFinding(
                        severity=ValidationSeverity.WARNING,
                        message=(
                            f"VEX suppression may be stale: fix available in "
                            f"{scan_finding.package_name} {scan_finding.fixed_version}"
                        ),
                        cve_id=cve_id,
                    ))
        for cve_id in all_scan_findings:
            if cve_id not in all_vex_cves:
                result.findings.append(ValidationFinding(
                    severity=ValidationSeverity.INFO,
                    message="CVE found in scan but has no VEX statement",
                    cve_id=cve_id,
                ))
        for cve_id, stmt in all_vex_cves.items():
            if cve_id not in all_scan_findings and stmt.status == VEXStatus.NOT_AFFECTED:
                result.findings.append(ValidationFinding(
                    severity=ValidationSeverity.INFO,
                    message="VEX suppression for CVE not found in current scans (may be resolved)",
                    cve_id=cve_id,
                ))
        return result
