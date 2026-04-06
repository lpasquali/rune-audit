"""Tests for VEX document validator."""

from __future__ import annotations

from rune_audit.models.cve import CVEFinding, CVEScanResult, CVESeverity
from rune_audit.models.vex import VEXDocument
from rune_audit.validators.vex_validator import ValidationSeverity, VEXValidator


def _make_vex_doc(stmts: list) -> VEXDocument:
    return VEXDocument.from_openvex({"@context": "https://openvex.dev/ns/v0.2.0", "@id": "test", "author": "test", "timestamp": "2026-04-01T00:00:00Z", "version": 1, "statements": stmts}, source_repo="test-repo")


class TestVEXValidatorDocument:
    def test_valid_document(self) -> None:
        doc = _make_vex_doc([{"vulnerability": {"name": "CVE-X"}, "status": "not_affected", "justification": "component_not_present", "impact_statement": "Not present."}])
        result = VEXValidator().validate_document(doc)
        assert not result.has_errors

    def test_not_affected_without_justification(self) -> None:
        doc = _make_vex_doc([{"vulnerability": {"name": "CVE-X"}, "status": "not_affected", "impact_statement": "Impact."}])
        result = VEXValidator().validate_document(doc)
        assert result.has_errors and result.error_count == 1

    def test_affected_without_action(self) -> None:
        doc = _make_vex_doc([{"vulnerability": {"name": "CVE-X"}, "status": "affected", "impact_statement": "Vuln."}])
        result = VEXValidator().validate_document(doc)
        assert result.has_warnings

    def test_missing_impact_statement(self) -> None:
        doc = _make_vex_doc([{"vulnerability": {"name": "CVE-X"}, "status": "fixed"}])
        result = VEXValidator().validate_document(doc)
        assert result.has_warnings

    def test_justification_strength_vcnp(self) -> None:
        doc = _make_vex_doc([{"vulnerability": {"name": "CVE-X"}, "status": "not_affected", "justification": "vulnerable_code_not_present"}])
        assert VEXValidator().validate_document(doc).has_warnings

    def test_justification_strength_cnp(self) -> None:
        doc = _make_vex_doc([{"vulnerability": {"name": "CVE-X"}, "status": "not_affected", "justification": "component_not_present"}])
        assert VEXValidator().validate_document(doc).has_warnings

    def test_justification_strength_adversary(self) -> None:
        doc = _make_vex_doc([{"vulnerability": {"name": "CVE-X"}, "status": "not_affected", "justification": "vulnerable_code_cannot_be_controlled_by_adversary"}])
        assert VEXValidator().validate_document(doc).has_warnings

    def test_justification_with_impact(self) -> None:
        doc = _make_vex_doc([{"vulnerability": {"name": "CVE-X"}, "status": "not_affected", "justification": "vulnerable_code_not_present", "impact_statement": "Not affected."}])
        assert not VEXValidator().validate_document(doc).has_errors

    def test_result_properties(self) -> None:
        doc = _make_vex_doc([{"vulnerability": {"name": "CVE-1"}, "status": "not_affected", "impact_statement": "OK"}, {"vulnerability": {"name": "CVE-2"}, "status": "affected", "impact_statement": "V."}])
        result = VEXValidator().validate_document(doc)
        assert result.error_count == 1 and result.warning_count == 1


class TestVEXValidatorCrossCheck:
    def test_stale_suppression(self) -> None:
        doc = _make_vex_doc([{"vulnerability": {"name": "CVE-X"}, "status": "not_affected", "justification": "component_not_present", "impact_statement": "Old."}])
        scan = CVEScanResult(findings=[CVEFinding(cve_id="CVE-X", severity=CVESeverity.HIGH, package_name="pkg", fixed_version="2.0.0")], scanner_name="grype")
        result = VEXValidator().cross_check([doc], [scan])
        assert any("stale" in f.message for f in result.findings if f.severity == ValidationSeverity.WARNING)

    def test_unaddressed_cve(self) -> None:
        doc = _make_vex_doc([])
        scan = CVEScanResult(findings=[CVEFinding(cve_id="CVE-NEW", severity=CVESeverity.HIGH)], scanner_name="grype")
        result = VEXValidator().cross_check([doc], [scan])
        assert any(f.cve_id == "CVE-NEW" for f in result.findings)

    def test_orphaned_suppression(self) -> None:
        doc = _make_vex_doc([{"vulnerability": {"name": "CVE-OLD"}, "status": "not_affected", "justification": "component_not_present", "impact_statement": "Removed."}])
        result = VEXValidator().cross_check([doc], [CVEScanResult(findings=[], scanner_name="grype")])
        assert any("not found in current scans" in f.message for f in result.findings)

    def test_no_issues(self) -> None:
        doc = _make_vex_doc([{"vulnerability": {"name": "CVE-X"}, "status": "not_affected", "justification": "component_not_present", "impact_statement": "OK."}])
        scan = CVEScanResult(findings=[CVEFinding(cve_id="CVE-X", severity=CVESeverity.LOW)], scanner_name="grype")
        assert not any(f.severity == ValidationSeverity.WARNING for f in VEXValidator().cross_check([doc], [scan]).findings)

    def test_empty_inputs(self) -> None:
        assert len(VEXValidator().cross_check([], []).findings) == 0
