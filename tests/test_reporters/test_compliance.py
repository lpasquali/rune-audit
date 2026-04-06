"""Tests for IEC 62443 ML4 compliance evidence matrix generator."""

from __future__ import annotations

import json

from rune_audit.models.cve import CVEFinding, CVEScanResult, CVESeverity
from rune_audit.models.evidence import EvidenceBundle
from rune_audit.models.gate import GateResult, GateStatus
from rune_audit.models.sbom import SBOMDocument
from rune_audit.models.slsa import SLSAAttestation
from rune_audit.models.vex import VEXDocument
from rune_audit.reporters.compliance import ComplianceMatrixGenerator, ComplianceStatus


def _make_vex_doc(statements_data: list) -> VEXDocument:
    return VEXDocument.from_openvex({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "test", "author": "test",
        "timestamp": "2026-04-01T00:00:00Z", "version": 1,
        "statements": statements_data,
    })


def _make_full_evidence() -> EvidenceBundle:
    """Create an EvidenceBundle with all evidence types populated."""
    sbom = SBOMDocument.from_cyclonedx(
        {"bomFormat": "CycloneDX", "specVersion": "1.5",
         "metadata": {"timestamp": "2026-04-01T00:00:00Z", "tools": {"components": [{"name": "syft", "version": "1.0"}]}},
         "components": [{"name": "pkg", "version": "1.0"}]},
        source_repo="lpasquali/rune",
    )
    grype = CVEScanResult(
        findings=[CVEFinding(cve_id="CVE-X", severity=CVESeverity.LOW)],
        scanner_name="grype", source_repo="lpasquali/rune",
    )
    vex_doc = _make_vex_doc([
        {"vulnerability": {"name": "CVE-X"}, "status": "not_affected",
         "justification": "component_not_present", "impact_statement": "OK."},
    ])
    slsa = SLSAAttestation(subject_digest="abc", builder_id="builder", source_repo="lpasquali/rune")
    gates = [
        GateResult(gate_name="RuneGate/Security/LicenseCompliance", status=GateStatus.PASS, source_repo="lpasquali/rune"),
        GateResult(gate_name="RuneGate/Security/SecretScanning", status=GateStatus.PASS, source_repo="lpasquali/rune"),
        GateResult(gate_name="RuneGate/SAST", status=GateStatus.PASS, source_repo="lpasquali/rune"),
    ]
    return EvidenceBundle(
        repos=["lpasquali/rune"],
        sboms=[sbom],
        cve_scans=[grype],
        vex_documents=[vex_doc],
        slsa_attestations=[slsa],
        gate_results=gates,
    )


class TestComplianceMatrixGenerator:
    def test_generate_full_evidence(self) -> None:
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(_make_full_evidence())
        assert matrix.total == 6
        assert len(matrix.repos_covered) == 1

    def test_generate_empty_evidence(self) -> None:
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(EvidenceBundle(repos=["lpasquali/rune"]))
        assert matrix.total == 6
        assert matrix.gap_count > 0

    def test_gate_requirement_met(self) -> None:
        evidence = EvidenceBundle(
            repos=["lpasquali/rune"],
            gate_results=[
                GateResult(gate_name="RuneGate/Security/LicenseCompliance", status=GateStatus.PASS, source_repo="lpasquali/rune"),
            ],
        )
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(evidence)
        sm2 = [r for r in matrix.requirements if r.requirement_id == "SM-2"][0]
        assert sm2.status == ComplianceStatus.MET

    def test_gate_requirement_failing(self) -> None:
        evidence = EvidenceBundle(
            repos=["lpasquali/rune"],
            gate_results=[
                GateResult(gate_name="RuneGate/Security/SecretScanning", status=GateStatus.FAIL, source_repo="lpasquali/rune"),
            ],
        )
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(evidence)
        sm8 = [r for r in matrix.requirements if r.requirement_id == "SM-8"][0]
        assert sm8.status == ComplianceStatus.NOT_MET

    def test_gate_requirement_partial(self) -> None:
        evidence = EvidenceBundle(
            repos=["lpasquali/rune", "lpasquali/rune-docs"],
            gate_results=[
                GateResult(gate_name="RuneGate/Security/SecretScanning", status=GateStatus.PASS, source_repo="lpasquali/rune"),
            ],
        )
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(evidence)
        sm8 = [r for r in matrix.requirements if r.requirement_id == "SM-8"][0]
        assert sm8.status == ComplianceStatus.PARTIALLY_MET

    def test_sbom_requirement_met(self) -> None:
        sbom = SBOMDocument.from_cyclonedx(
            {"bomFormat": "CycloneDX", "components": [{"name": "a"}],
             "metadata": {"timestamp": "2026-04-01T00:00:00Z", "tools": {"components": [{"name": "syft", "version": "1.0"}]}}},
            source_repo="lpasquali/rune",
        )
        slsa = SLSAAttestation(subject_digest="abc", source_repo="lpasquali/rune")
        evidence = EvidenceBundle(repos=["lpasquali/rune"], sboms=[sbom], slsa_attestations=[slsa])
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(evidence)
        sm9 = [r for r in matrix.requirements if r.requirement_id == "SM-9"][0]
        assert sm9.status == ComplianceStatus.MET

    def test_sbom_requirement_partial_no_slsa(self) -> None:
        sbom = SBOMDocument.from_cyclonedx(
            {"bomFormat": "CycloneDX", "components": [{"name": "a"}], "metadata": {"timestamp": "2026-04-01T00:00:00Z"}},
            source_repo="lpasquali/rune",
        )
        evidence = EvidenceBundle(repos=["lpasquali/rune"], sboms=[sbom])
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(evidence)
        sm9 = [r for r in matrix.requirements if r.requirement_id == "SM-9"][0]
        assert sm9.status == ComplianceStatus.PARTIALLY_MET

    def test_vex_requirement(self) -> None:
        vex_doc = _make_vex_doc([
            {"vulnerability": {"name": "CVE-X"}, "status": "not_affected",
             "justification": "component_not_present", "impact_statement": "OK."},
        ])
        scan = CVEScanResult(findings=[
            CVEFinding(cve_id="CVE-X", severity=CVESeverity.LOW),
        ], scanner_name="grype")
        evidence = EvidenceBundle(repos=["lpasquali/rune"], cve_scans=[scan], vex_documents=[vex_doc])
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(evidence)
        dm4 = [r for r in matrix.requirements if r.requirement_id == "DM-4"][0]
        assert dm4.status == ComplianceStatus.MET

    def test_vex_requirement_unsuppressed(self) -> None:
        scan = CVEScanResult(findings=[
            CVEFinding(cve_id="CVE-UNSUPPRESSED", severity=CVESeverity.HIGH),
        ], scanner_name="grype")
        evidence = EvidenceBundle(repos=["lpasquali/rune"], cve_scans=[scan])
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(evidence)
        dm4 = [r for r in matrix.requirements if r.requirement_id == "DM-4"][0]
        assert dm4.status == ComplianceStatus.PARTIALLY_MET
        assert any("CVE-UNSUPPRESSED" in g for g in dm4.gaps)


class TestComplianceRenderers:
    def test_render_markdown(self) -> None:
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(_make_full_evidence())
        md = gen.render_markdown(matrix)
        assert "# IEC 62443-4-1 ML4 Compliance Evidence Matrix" in md
        assert "SM-2" in md
        assert "DM-4" in md
        assert "|" in md

    def test_render_json(self) -> None:
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(_make_full_evidence())
        json_str = gen.render_json(matrix)
        data = json.loads(json_str)
        assert "requirements" in data
        assert len(data["requirements"]) == 6

    def test_render_html(self) -> None:
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(_make_full_evidence())
        html = gen.render_html(matrix)
        assert "<table>" in html
        assert "SM-2" in html
        assert "</table>" in html

    def test_get_gaps(self) -> None:
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(EvidenceBundle(repos=["lpasquali/rune"]))
        gaps = gen.get_gaps(matrix)
        assert len(gaps) > 0
        assert all(g.status != ComplianceStatus.MET for g in gaps)

    def test_matrix_properties(self) -> None:
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(_make_full_evidence())
        assert matrix.total == 6
        assert matrix.met_count + matrix.gap_count <= matrix.total
