# SPDX-License-Identifier: Apache-2.0
"""Tests for ReportGenerator -- full, summary, and delta reports."""

from __future__ import annotations

import json

from rune_audit.models.cve import CVEFinding, CVEScanResult, CVESeverity
from rune_audit.models.evidence import EvidenceBundle
from rune_audit.models.gate import GateResult, GateStatus
from rune_audit.models.sbom import SBOMComponent, SBOMDocument, SBOMToolMetadata
from rune_audit.models.slsa import SLSAAttestation
from rune_audit.models.vex import VEXDocument, VEXStatement, VEXStatus
from rune_audit.reporters.report_generator import ReportGenerator


def _make_sbom(repo="lpasquali/rune", components=None):
    return SBOMDocument(
        bomFormat="CycloneDX",
        specVersion="1.5",
        components=components
        or [
            SBOMComponent(name="pydantic", version="2.7.0", licenses=["MIT"]),
            SBOMComponent(name="httpx", version="0.27.0", licenses=["BSD-3-Clause"]),
            SBOMComponent(name="tar", version="1.35"),
        ],
        tools=[SBOMToolMetadata(vendor="Anchore", name="syft", version="1.4.0")],
        source_repo=repo,
    )


def _make_cve_scan(repo="lpasquali/rune", findings=None):
    return CVEScanResult(
        findings=findings
        or [
            CVEFinding(
                cve_id="CVE-2024-1234",
                severity=CVESeverity.HIGH,
                cvss_score=8.8,
                package_name="test-pkg",
                package_version="1.0.0",
                fixed_version="2.0.1",
            ),
            CVEFinding(
                cve_id="CVE-2005-2541",
                severity=CVESeverity.LOW,
                cvss_score=2.1,
                package_name="tar",
                package_version="1.35",
            ),
        ],
        scanner_name="grype",
        source_repo=repo,
    )


def _make_vex_doc(repo="lpasquali/rune"):
    return VEXDocument(
        **{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "urn:test:vex:1"},
        author="test",
        timestamp="2026-04-01T00:00:00+00:00",
        version=1,
        statements=[VEXStatement(vulnerability_name="CVE-2005-2541", status=VEXStatus.NOT_AFFECTED)],
        source_repo=repo,
    )


def _make_slsa(repo="lpasquali/rune", verified=True):
    return SLSAAttestation(
        subject_name="ghcr.io/lpasquali/rune",
        builder_id="https://github.com/actions/runner/",
        build_type="https://actions.github.io/buildtypes/workflow/v1",
        source_repo=repo,
        verified=verified,
    )


def _make_full_bundle():
    return EvidenceBundle(
        repos=["lpasquali/rune"],
        sboms=[_make_sbom()],
        cve_scans=[_make_cve_scan()],
        vex_documents=[_make_vex_doc()],
        slsa_attestations=[_make_slsa()],
        gate_results=[
            GateResult(gate_name="license-check", status=GateStatus.PASS, source_repo="lpasquali/rune"),
            GateResult(gate_name="secret-scan", status=GateStatus.PASS, source_repo="lpasquali/rune"),
            GateResult(gate_name="sast-check", status=GateStatus.PASS, source_repo="lpasquali/rune"),
        ],
    )


class TestGenerateFullMarkdown:
    def test_sections_present(self):
        report = ReportGenerator(_make_full_bundle()).generate_full(output_format="markdown")
        for s in [
            "# RUNE Audit Report",
            "## Executive Summary",
            "## SBOM Analysis",
            "## CVE Findings",
            "## VEX Status",
            "## SLSA Verification",
            "## Compliance Matrix",
            "## Recommendations",
        ]:
            assert s in report

    def test_sbom_data(self):
        report = ReportGenerator(_make_full_bundle()).generate_full(output_format="markdown")
        assert "Total components**: 3" in report and "MIT" in report

    def test_cve_findings(self):
        report = ReportGenerator(_make_full_bundle()).generate_full(output_format="markdown")
        assert "CVE-2024-1234" in report and "High" in report

    def test_vex_status(self):
        report = ReportGenerator(_make_full_bundle()).generate_full(output_format="markdown")
        assert "VEX documents**: 1" in report

    def test_slsa(self):
        report = ReportGenerator(_make_full_bundle()).generate_full(output_format="markdown")
        assert "lpasquali/rune" in report and "Yes" in report

    def test_recommendations_with_high_cve(self):
        report = ReportGenerator(_make_full_bundle()).generate_full(output_format="markdown")
        assert "Upgrade test-pkg to 2.0.1" in report


class TestGenerateFullJson:
    def test_valid(self):
        data = json.loads(ReportGenerator(_make_full_bundle()).generate_full(output_format="json"))
        assert data["title"] == "RUNE Audit Report"

    def test_cve_findings(self):
        data = json.loads(ReportGenerator(_make_full_bundle()).generate_full(output_format="json"))
        assert data["cve_findings"]["total"] == 2

    def test_slsa(self):
        data = json.loads(ReportGenerator(_make_full_bundle()).generate_full(output_format="json"))
        assert data["slsa_verification"]["lpasquali/rune"]["verified"] is True

    def test_compliance(self):
        data = json.loads(ReportGenerator(_make_full_bundle()).generate_full(output_format="json"))
        assert data["compliance_matrix"]["total"] > 0

    def test_recommendations(self):
        data = json.loads(ReportGenerator(_make_full_bundle()).generate_full(output_format="json"))
        assert len(data["recommendations"]) > 0


class TestGenerateSummary:
    def test_no_critical(self):
        bundle = EvidenceBundle(
            repos=["lpasquali/rune"],
            gate_results=[
                GateResult(gate_name="license-check", status=GateStatus.PASS, source_repo="lpasquali/rune"),
                GateResult(gate_name="secret-scan", status=GateStatus.PASS, source_repo="lpasquali/rune"),
                GateResult(gate_name="sast-check", status=GateStatus.PASS, source_repo="lpasquali/rune"),
            ],
            sboms=[_make_sbom()],
            vex_documents=[_make_vex_doc()],
            slsa_attestations=[_make_slsa()],
        )
        report = ReportGenerator(bundle).generate_summary(output_format="markdown")
        assert "# RUNE Audit Summary" in report and "Critical Findings" not in report

    def test_with_critical_cves(self):
        report = ReportGenerator(_make_full_bundle()).generate_summary(output_format="markdown")
        assert "## Critical Findings" in report and "CVE-2024-1234" in report

    def test_needs_attention(self):
        bundle = EvidenceBundle(
            repos=["lpasquali/rune"],
            gate_results=[GateResult(gate_name="sast-check", status=GateStatus.FAIL, source_repo="lpasquali/rune")],
        )
        report = ReportGenerator(bundle).generate_summary(output_format="markdown")
        assert "NEEDS ATTENTION" in report

    def test_json(self):
        data = json.loads(ReportGenerator(_make_full_bundle()).generate_summary(output_format="json"))
        assert data["title"] == "RUNE Audit Summary" and data["key_metrics"]["total_cves"] == 2

    def test_json_overall_status(self):
        data = json.loads(ReportGenerator(_make_full_bundle()).generate_summary(output_format="json"))
        assert data["overall_status"] in ("PASS", "NEEDS ATTENTION")


class TestGenerateDelta:
    def test_new_cves(self):
        report = ReportGenerator(EvidenceBundle(repos=["lpasquali/rune"], cve_scans=[_make_cve_scan()])).generate_delta(
            EvidenceBundle(repos=["lpasquali/rune"]), output_format="markdown"
        )
        assert "CVE-2024-1234" in report and "New CVEs" in report

    def test_resolved_cves(self):
        report = ReportGenerator(EvidenceBundle(repos=["lpasquali/rune"])).generate_delta(
            EvidenceBundle(repos=["lpasquali/rune"], cve_scans=[_make_cve_scan()]), output_format="markdown"
        )
        assert "Resolved CVEs" in report and "CVE-2024-1234" in report

    def test_new_components(self):
        report = ReportGenerator(EvidenceBundle(repos=["lpasquali/rune"], sboms=[_make_sbom()])).generate_delta(
            EvidenceBundle(repos=["lpasquali/rune"]), output_format="markdown"
        )
        assert "New components" in report and "pydantic@2.7.0" in report

    def test_removed_components(self):
        report = ReportGenerator(EvidenceBundle(repos=["lpasquali/rune"])).generate_delta(
            EvidenceBundle(repos=["lpasquali/rune"], sboms=[_make_sbom()]), output_format="markdown"
        )
        assert "Removed components" in report and "pydantic@2.7.0" in report

    def test_compliance_changes(self):
        report = ReportGenerator(
            EvidenceBundle(
                repos=["lpasquali/rune"],
                gate_results=[
                    GateResult(gate_name="license-check", status=GateStatus.PASS, source_repo="lpasquali/rune")
                ],
            )
        ).generate_delta(EvidenceBundle(repos=["lpasquali/rune"]), output_format="markdown")
        assert "Compliance Changes" in report

    def test_no_changes(self):
        b = EvidenceBundle(repos=["lpasquali/rune"])
        report = ReportGenerator(b).generate_delta(b, output_format="markdown")
        for msg in [
            "No new CVEs.",
            "No resolved CVEs.",
            "No new components.",
            "No removed components.",
            "No compliance status changes.",
        ]:
            assert msg in report

    def test_json(self):
        data = json.loads(
            ReportGenerator(
                EvidenceBundle(repos=["lpasquali/rune"], cve_scans=[_make_cve_scan()], sboms=[_make_sbom()])
            ).generate_delta(EvidenceBundle(repos=["lpasquali/rune"]), output_format="json")
        )
        assert "CVE-2024-1234" in data["cve_changes"]["new_cves"]
        assert len(data["component_changes"]["new_components"]) == 3


class TestEdgeCases:
    def test_empty_bundle_full(self):
        report = ReportGenerator(EvidenceBundle(repos=[])).generate_full(output_format="markdown")
        assert "Total components**: 0" in report and "Total findings: 0" in report
        assert "No SLSA attestations collected." in report

    def test_empty_bundle_summary(self):
        report = ReportGenerator(EvidenceBundle(repos=[])).generate_summary(output_format="markdown")
        assert "Repos covered**: 0" in report

    def test_empty_bundle_delta(self):
        b = EvidenceBundle(repos=[])
        result = ReportGenerator(b).generate_delta(b, output_format="markdown")
        assert "# RUNE Audit Delta Report" in result

    def test_only_sboms(self):
        gen = ReportGenerator(EvidenceBundle(repos=["lpasquali/rune"], sboms=[_make_sbom()]))
        report = gen.generate_full(output_format="markdown")
        assert "Total components**: 3" in report and "Total findings: 0" in report

    def test_only_cves(self):
        gen = ReportGenerator(
            EvidenceBundle(repos=["lpasquali/rune"], cve_scans=[_make_cve_scan()]),
        )
        report = gen.generate_full(output_format="markdown")
        assert "Total components**: 0" in report and "CVE-2024-1234" in report

    def test_only_slsa(self):
        gen = ReportGenerator(
            EvidenceBundle(repos=["lpasquali/rune"], slsa_attestations=[_make_slsa()]),
        )
        report = gen.generate_full(output_format="markdown")
        assert "lpasquali/rune" in report

    def test_critical_cve_rec(self):
        finding = CVEFinding(
            cve_id="CVE-2024-9999",
            severity=CVESeverity.CRITICAL,
            cvss_score=10.0,
            package_name="vulnerable-pkg",
        )
        bundle = EvidenceBundle(
            repos=["lpasquali/rune"],
            cve_scans=[CVEScanResult(findings=[finding], source_repo="lpasquali/rune")],
        )
        assert "CRITICAL: Remediate CVE-2024-9999" in ReportGenerator(bundle).generate_full(output_format="markdown")

    def test_no_issues_rec(self):
        bundle = EvidenceBundle(
            repos=["lpasquali/rune"],
            gate_results=[
                GateResult(gate_name="license-check", status=GateStatus.PASS, source_repo="lpasquali/rune"),
                GateResult(gate_name="secret-scan", status=GateStatus.PASS, source_repo="lpasquali/rune"),
                GateResult(gate_name="sast-check", status=GateStatus.PASS, source_repo="lpasquali/rune"),
            ],
            sboms=[_make_sbom()],
            vex_documents=[_make_vex_doc()],
            slsa_attestations=[_make_slsa()],
        )
        data = json.loads(ReportGenerator(bundle).generate_full(output_format="json"))
        assert isinstance(data["recommendations"], list)

    def test_slsa_not_verified(self):
        report = ReportGenerator(
            EvidenceBundle(repos=["lpasquali/rune"], slsa_attestations=[_make_slsa(verified=False)])
        ).generate_full(output_format="markdown")
        assert "No" in report

    def test_unsuppressed_cves_rec(self):
        data = json.loads(
            ReportGenerator(EvidenceBundle(repos=["lpasquali/rune"], cve_scans=[_make_cve_scan()])).generate_full(
                output_format="json"
            )
        )
        assert any("unsuppressed" in r.lower() for r in data["recommendations"])

    def test_no_slsa_rec(self):
        data = json.loads(ReportGenerator(EvidenceBundle(repos=["lpasquali/rune"])).generate_full(output_format="json"))
        assert any("slsa" in r.lower() for r in data["recommendations"])

    def test_empty_full_json(self):
        data = json.loads(ReportGenerator(EvidenceBundle(repos=[])).generate_full(output_format="json"))
        assert data["sbom_analysis"]["total_components"] == 0 and data["slsa_verification"] == {}

    def test_unknown_license(self):
        bundle = EvidenceBundle(
            repos=["lpasquali/rune"],
            sboms=[
                SBOMDocument(
                    bomFormat="CycloneDX",
                    specVersion="1.5",
                    components=[SBOMComponent(name="nolicense", version="1.0")],
                    source_repo="lpasquali/rune",
                )
            ],
        )
        data = json.loads(ReportGenerator(bundle).generate_full(output_format="json"))
        assert data["sbom_analysis"]["license_breakdown"]["Unknown"] == 1
