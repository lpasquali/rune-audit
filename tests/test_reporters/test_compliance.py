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


def _make_vex_doc(stmts):
    return VEXDocument.from_openvex(
        {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "t",
            "author": "t",
            "timestamp": "2026-04-01T00:00:00Z",
            "version": 1,
            "statements": stmts,
        }
    )


def _make_full_evidence() -> EvidenceBundle:
    sbom = SBOMDocument.from_cyclonedx(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "timestamp": "2026-04-01T00:00:00Z",
                "tools": {"components": [{"name": "syft", "version": "1.0"}]},
            },
            "components": [{"name": "pkg"}],
        },
        source_repo="lpasquali/rune",
    )
    grype = CVEScanResult(
        findings=[CVEFinding(cve_id="CVE-X", severity=CVESeverity.LOW)],
        scanner_name="grype",
        source_repo="lpasquali/rune",
    )
    vex = _make_vex_doc(
        [
            {
                "vulnerability": {"name": "CVE-X"},
                "status": "not_affected",
                "justification": "component_not_present",
                "impact_statement": "OK.",
            }
        ]
    )
    slsa = SLSAAttestation(subject_digest="abc", builder_id="b", source_repo="lpasquali/rune")
    gates = [
        GateResult(
            gate_name="RuneGate/Security/LicenseCompliance", status=GateStatus.PASS, source_repo="lpasquali/rune"
        ),
        GateResult(gate_name="RuneGate/Security/SecretScanning", status=GateStatus.PASS, source_repo="lpasquali/rune"),
        GateResult(gate_name="RuneGate/SAST", status=GateStatus.PASS, source_repo="lpasquali/rune"),
    ]
    return EvidenceBundle(
        repos=["lpasquali/rune"],
        sboms=[sbom],
        cve_scans=[grype],
        vex_documents=[vex],
        slsa_attestations=[slsa],
        gate_results=gates,
    )


class TestComplianceMatrixGenerator:
    def test_generate_full(self) -> None:
        matrix = ComplianceMatrixGenerator().generate(_make_full_evidence())
        assert matrix.total == 6
        assert len(matrix.repos_covered) == 1

    def test_generate_empty(self) -> None:
        matrix = ComplianceMatrixGenerator().generate(EvidenceBundle(repos=["lpasquali/rune"]))
        assert matrix.total == 6 and matrix.gap_count > 0

    def test_gate_met(self) -> None:
        evidence = EvidenceBundle(
            repos=["r"],
            gate_results=[
                GateResult(gate_name="RuneGate/Security/LicenseCompliance", status=GateStatus.PASS, source_repo="r")
            ],
        )
        sm2 = [r for r in ComplianceMatrixGenerator().generate(evidence).requirements if r.requirement_id == "SM-2"][0]
        assert sm2.status == ComplianceStatus.MET

    def test_gate_failing(self) -> None:
        evidence = EvidenceBundle(
            repos=["r"],
            gate_results=[
                GateResult(gate_name="RuneGate/Security/SecretScanning", status=GateStatus.FAIL, source_repo="r")
            ],
        )
        sm8 = [r for r in ComplianceMatrixGenerator().generate(evidence).requirements if r.requirement_id == "SM-8"][0]
        assert sm8.status == ComplianceStatus.NOT_MET

    def test_gate_partial(self) -> None:
        evidence = EvidenceBundle(
            repos=["r1", "r2"],
            gate_results=[
                GateResult(gate_name="RuneGate/Security/SecretScanning", status=GateStatus.PASS, source_repo="r1")
            ],
        )
        sm8 = [r for r in ComplianceMatrixGenerator().generate(evidence).requirements if r.requirement_id == "SM-8"][0]
        assert sm8.status == ComplianceStatus.PARTIALLY_MET

    def test_sbom_met(self) -> None:
        sbom = SBOMDocument.from_cyclonedx(
            {
                "bomFormat": "CycloneDX",
                "components": [{"name": "a"}],
                "metadata": {
                    "timestamp": "2026-04-01T00:00:00Z",
                    "tools": {"components": [{"name": "syft", "version": "1.0"}]},
                },
            },
            source_repo="r",
        )
        slsa = SLSAAttestation(subject_digest="abc", source_repo="r")
        sm9 = [
            r
            for r in ComplianceMatrixGenerator()
            .generate(EvidenceBundle(repos=["r"], sboms=[sbom], slsa_attestations=[slsa]))
            .requirements
            if r.requirement_id == "SM-9"
        ][0]
        assert sm9.status == ComplianceStatus.MET

    def test_sbom_partial_no_slsa(self) -> None:
        sbom = SBOMDocument.from_cyclonedx(
            {
                "bomFormat": "CycloneDX",
                "components": [{"name": "a"}],
                "metadata": {"timestamp": "2026-04-01T00:00:00Z"},
            },
            source_repo="r",
        )
        sm9 = [
            r
            for r in ComplianceMatrixGenerator().generate(EvidenceBundle(repos=["r"], sboms=[sbom])).requirements
            if r.requirement_id == "SM-9"
        ][0]
        assert sm9.status == ComplianceStatus.PARTIALLY_MET

    def test_vex_met(self) -> None:
        vex = _make_vex_doc(
            [
                {
                    "vulnerability": {"name": "CVE-X"},
                    "status": "not_affected",
                    "justification": "component_not_present",
                    "impact_statement": "OK.",
                }
            ]
        )
        scan = CVEScanResult(findings=[CVEFinding(cve_id="CVE-X", severity=CVESeverity.LOW)], scanner_name="grype")
        dm4 = [
            r
            for r in ComplianceMatrixGenerator()
            .generate(EvidenceBundle(repos=["r"], cve_scans=[scan], vex_documents=[vex]))
            .requirements
            if r.requirement_id == "DM-4"
        ][0]
        assert dm4.status == ComplianceStatus.MET

    def test_vex_unsuppressed(self) -> None:
        scan = CVEScanResult(findings=[CVEFinding(cve_id="CVE-U", severity=CVESeverity.HIGH)], scanner_name="grype")
        dm4 = [
            r
            for r in ComplianceMatrixGenerator().generate(EvidenceBundle(repos=["r"], cve_scans=[scan])).requirements
            if r.requirement_id == "DM-4"
        ][0]
        assert dm4.status == ComplianceStatus.PARTIALLY_MET


class TestComplianceRenderers:
    def test_render_markdown(self) -> None:
        gen = ComplianceMatrixGenerator()
        md = gen.render_markdown(gen.generate(_make_full_evidence()))
        assert "# IEC 62443" in md and "SM-2" in md

    def test_render_json(self) -> None:
        gen = ComplianceMatrixGenerator()
        data = json.loads(gen.render_json(gen.generate(_make_full_evidence())))
        assert "requirements" in data and len(data["requirements"]) == 6

    def test_render_html(self) -> None:
        gen = ComplianceMatrixGenerator()
        html = gen.render_html(gen.generate(_make_full_evidence()))
        assert "<table>" in html and "SM-2" in html

    def test_get_gaps(self) -> None:
        gen = ComplianceMatrixGenerator()
        gaps = gen.get_gaps(gen.generate(EvidenceBundle(repos=["r"])))
        assert len(gaps) > 0

    def test_matrix_properties(self) -> None:
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(_make_full_evidence())
        assert matrix.total == 6
        assert matrix.met_count + matrix.gap_count <= matrix.total


class TestComplianceEdgeCases:
    def test_vex_no_scans_no_vex(self) -> None:
        """DM-4 with no evidence at all."""
        evidence = EvidenceBundle(repos=["r"])
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(evidence)
        dm4 = [r for r in matrix.requirements if r.requirement_id == "DM-4"][0]
        assert dm4.status == ComplianceStatus.NOT_MET

    def test_sbom_missing_from_some_repos(self) -> None:
        """SM-9 with SBOM from only some repos."""
        sbom = SBOMDocument.from_cyclonedx(
            {
                "bomFormat": "CycloneDX",
                "components": [{"name": "a"}],
                "metadata": {"timestamp": "2026-04-01T00:00:00Z"},
            },
            source_repo="r1",
        )
        evidence = EvidenceBundle(repos=["r1", "r2"], sboms=[sbom])
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(evidence)
        sm9 = [r for r in matrix.requirements if r.requirement_id == "SM-9"][0]
        assert sm9.status == ComplianceStatus.PARTIALLY_MET
        assert any("r2" in g for g in sm9.gaps)

    def test_no_sboms(self) -> None:
        """SM-9 with no SBOMs."""
        evidence = EvidenceBundle(repos=["r"])
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(evidence)
        sm9 = [r for r in matrix.requirements if r.requirement_id == "SM-9"][0]
        assert sm9.status == ComplianceStatus.NOT_MET

    def test_no_gate_results(self) -> None:
        """Gate requirement with no gate results."""
        evidence = EvidenceBundle(repos=["r"])
        gen = ComplianceMatrixGenerator()
        matrix = gen.generate(evidence)
        sm2 = [r for r in matrix.requirements if r.requirement_id == "SM-2"][0]
        assert sm2.status == ComplianceStatus.NOT_MET

    def test_vex_only_scans_no_vex_docs(self) -> None:
        """DM-4 with scans but no VEX documents."""
        scan = CVEScanResult(findings=[CVEFinding(cve_id="CVE-X", severity=CVESeverity.LOW)], scanner_name="grype")
        evidence = EvidenceBundle(repos=["r"], cve_scans=[scan])
        gen = ComplianceMatrixGenerator()
        dm4 = [r for r in gen.generate(evidence).requirements if r.requirement_id == "DM-4"][0]
        assert dm4.status == ComplianceStatus.PARTIALLY_MET

    def test_vex_only_vex_docs_no_scans(self) -> None:
        """DM-4 with VEX but no scans."""
        vex = _make_vex_doc(
            [
                {
                    "vulnerability": {"name": "CVE-X"},
                    "status": "not_affected",
                    "justification": "component_not_present",
                    "impact_statement": "OK.",
                }
            ]
        )
        evidence = EvidenceBundle(repos=["r"], vex_documents=[vex])
        gen = ComplianceMatrixGenerator()
        dm4 = [r for r in gen.generate(evidence).requirements if r.requirement_id == "DM-4"][0]
        assert dm4.status == ComplianceStatus.PARTIALLY_MET
