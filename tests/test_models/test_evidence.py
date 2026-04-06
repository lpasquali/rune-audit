"""Tests for evidence bundle model."""

from __future__ import annotations

from rune_audit.models.cve import CVEFinding, CVEScanResult, CVESeverity
from rune_audit.models.evidence import EvidenceBundle
from rune_audit.models.gate import GateResult, GateStatus
from rune_audit.models.vex import VEXDocument, VEXStatement, VEXStatus
from tests.conftest import make_evidence_bundle, make_gate_result


def test_evidence_bundle_empty() -> None:
    """Empty EvidenceBundle has sensible defaults."""
    bundle = EvidenceBundle()
    assert bundle.repos == []
    assert bundle.sboms == []
    assert bundle.cve_scans == []
    assert bundle.gate_results == []
    assert bundle.collected_at is not None


def test_evidence_bundle_all_cve_ids() -> None:
    """all_cve_ids aggregates CVE IDs from all scans."""
    bundle = EvidenceBundle(
        cve_scans=[
            CVEScanResult(
                findings=[
                    CVEFinding(cve_id="CVE-2024-0001", severity=CVESeverity.HIGH),
                    CVEFinding(cve_id="CVE-2024-0002", severity=CVESeverity.LOW),
                ],
                scanner_name="grype",
            ),
            CVEScanResult(
                findings=[
                    CVEFinding(cve_id="CVE-2024-0001", severity=CVESeverity.HIGH),
                    CVEFinding(cve_id="CVE-2024-0003", severity=CVESeverity.MEDIUM),
                ],
                scanner_name="trivy",
            ),
        ]
    )
    ids = bundle.all_cve_ids()
    assert ids == {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}


def test_evidence_bundle_suppressed_cves() -> None:
    """all_suppressed_cves aggregates from VEX documents."""
    bundle = EvidenceBundle(
        vex_documents=[
            VEXDocument(
                statements=[
                    VEXStatement(vulnerability_id="CVE-2024-0001", status=VEXStatus.NOT_AFFECTED),
                ]
            ),
        ]
    )
    assert bundle.all_suppressed_cves() == {"CVE-2024-0001"}


def test_evidence_bundle_unsuppressed_cves() -> None:
    """unsuppressed_cves returns only non-VEX-suppressed CVEs."""
    bundle = EvidenceBundle(
        cve_scans=[
            CVEScanResult(
                findings=[
                    CVEFinding(cve_id="CVE-2024-0001", severity=CVESeverity.HIGH),
                    CVEFinding(cve_id="CVE-2024-0002", severity=CVESeverity.LOW),
                ],
                scanner_name="grype",
            ),
        ],
        vex_documents=[
            VEXDocument(
                statements=[
                    VEXStatement(vulnerability_id="CVE-2024-0001", status=VEXStatus.NOT_AFFECTED),
                ]
            ),
        ],
    )
    assert bundle.unsuppressed_cves() == {"CVE-2024-0002"}


def test_evidence_bundle_gates_passing() -> None:
    """gates_passing returns True when all gates pass."""
    bundle = make_evidence_bundle()
    assert bundle.gates_passing() is True


def test_evidence_bundle_gates_failing() -> None:
    """gates_passing returns False when any gate fails."""
    bundle = EvidenceBundle(
        gate_results=[
            GateResult(gate_name="coverage", status=GateStatus.PASS, message="OK"),
            GateResult(gate_name="sast", status=GateStatus.FAIL, message="Findings"),
        ]
    )
    assert bundle.gates_passing() is False


def test_evidence_bundle_gates_empty() -> None:
    """gates_passing returns True when no gates (vacuous truth)."""
    bundle = EvidenceBundle()
    assert bundle.gates_passing() is True


def test_make_gate_result_factory() -> None:
    """Factory produces valid GateResult."""
    result = make_gate_result(status=GateStatus.FAIL)
    assert result.status == GateStatus.FAIL


def test_make_evidence_bundle_factory() -> None:
    """Factory produces valid EvidenceBundle."""
    bundle = make_evidence_bundle(repos=["repo-a", "repo-b"])
    assert bundle.repos == ["repo-a", "repo-b"]
    assert len(bundle.gate_results) == 3
