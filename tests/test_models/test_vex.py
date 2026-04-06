"""Tests for VEX document models."""

from __future__ import annotations

from rune_audit.models.vex import VEXDocument, VEXStatement, VEXStatus


def test_vex_status_values() -> None:
    """VEXStatus has expected enum values."""
    assert VEXStatus.NOT_AFFECTED.value == "not_affected"
    assert VEXStatus.AFFECTED.value == "affected"
    assert VEXStatus.FIXED.value == "fixed"
    assert VEXStatus.UNDER_INVESTIGATION.value == "under_investigation"


def test_vex_statement_creation() -> None:
    """VEXStatement can be created with all fields."""
    stmt = VEXStatement(
        vulnerability_id="CVE-2024-0001",
        status=VEXStatus.NOT_AFFECTED,
        justification="vulnerable_code_not_in_execute_path",
        impact_statement="Not reachable",
    )
    assert stmt.vulnerability_id == "CVE-2024-0001"
    assert stmt.status == VEXStatus.NOT_AFFECTED


def test_vex_document_get_suppressed_cves() -> None:
    """get_suppressed_cves returns only not_affected CVEs."""
    doc = VEXDocument(
        statements=[
            VEXStatement(vulnerability_id="CVE-2024-0001", status=VEXStatus.NOT_AFFECTED),
            VEXStatement(vulnerability_id="CVE-2024-0002", status=VEXStatus.AFFECTED),
            VEXStatement(vulnerability_id="CVE-2024-0003", status=VEXStatus.NOT_AFFECTED),
        ]
    )
    suppressed = doc.get_suppressed_cves()
    assert suppressed == {"CVE-2024-0001", "CVE-2024-0003"}


def test_vex_document_empty() -> None:
    """Empty VEXDocument has no suppressed CVEs."""
    doc = VEXDocument()
    assert doc.get_suppressed_cves() == set()
    assert doc.version == 1
