"""Tests for evidence bundle model."""
from rune_audit.models.cve import CVEFinding, CVEScanResult, CVESeverity
from rune_audit.models.evidence import EvidenceBundle
from rune_audit.models.gate import GateResult, GateStatus
from rune_audit.models.vex import VEXDocument

def _vex(stmts):
    return VEXDocument.from_openvex({"@context": "https://openvex.dev/ns/v0.2.0", "@id": "t", "author": "t",
        "timestamp": "2026-01-01T00:00:00Z", "version": 1, "statements": stmts})

def test_empty():
    b = EvidenceBundle()
    assert b.repos == [] and b.sboms == [] and b.collected_at is not None

def test_all_cve_ids():
    b = EvidenceBundle(cve_scans=[
        CVEScanResult(findings=[CVEFinding(cve_id="CVE-1", severity=CVESeverity.HIGH), CVEFinding(cve_id="CVE-2", severity=CVESeverity.LOW)], scanner_name="g"),
        CVEScanResult(findings=[CVEFinding(cve_id="CVE-1", severity=CVESeverity.HIGH), CVEFinding(cve_id="CVE-3", severity=CVESeverity.MEDIUM)], scanner_name="t"),
    ])
    assert b.all_cve_ids() == {"CVE-1", "CVE-2", "CVE-3"}

def test_suppressed():
    doc = _vex([{"vulnerability": {"name": "CVE-1"}, "status": "not_affected", "justification": "component_not_present", "impact_statement": "N/A"}])
    assert EvidenceBundle(vex_documents=[doc]).all_suppressed_cves() == {"CVE-1"}

def test_unsuppressed():
    doc = _vex([{"vulnerability": {"name": "CVE-1"}, "status": "not_affected", "justification": "component_not_present", "impact_statement": "N/A"}])
    b = EvidenceBundle(cve_scans=[CVEScanResult(findings=[CVEFinding(cve_id="CVE-1", severity=CVESeverity.HIGH), CVEFinding(cve_id="CVE-2", severity=CVESeverity.LOW)], scanner_name="g")], vex_documents=[doc])
    assert b.unsuppressed_cves() == {"CVE-2"}

def test_gates_passing():
    assert EvidenceBundle(gate_results=[GateResult(gate_name="a", status=GateStatus.PASS)]).gates_passing()

def test_gates_failing():
    assert not EvidenceBundle(gate_results=[GateResult(gate_name="a", status=GateStatus.FAIL)]).gates_passing()

def test_gates_empty():
    assert EvidenceBundle().gates_passing()
