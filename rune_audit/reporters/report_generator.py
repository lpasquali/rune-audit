# SPDX-License-Identifier: Apache-2.0
"""Audit report generator producing full, summary, and delta reports."""

from __future__ import annotations

import json
from collections import Counter
from typing import TYPE_CHECKING, Any

from rune_audit.models.cve import CVESeverity
from rune_audit.reporters.compliance import ComplianceMatrixGenerator

if TYPE_CHECKING:
    from rune_audit.models.evidence import EvidenceBundle


class ReportGenerator:
    """Generate audit reports from evidence bundles."""

    def __init__(self, evidence: EvidenceBundle) -> None:
        self._evidence = evidence
        self._compliance_gen = ComplianceMatrixGenerator()

    def generate_full(self, format: str = "markdown") -> str:
        data = self._build_full_data()
        if format == "json":
            return json.dumps(data, indent=2, default=str)
        return self._render_full_markdown(data)

    def generate_summary(self, format: str = "markdown") -> str:
        data = self._build_summary_data()
        if format == "json":
            return json.dumps(data, indent=2, default=str)
        return self._render_summary_markdown(data)

    def generate_delta(self, previous: EvidenceBundle, format: str = "markdown") -> str:
        data = self._build_delta_data(previous)
        if format == "json":
            return json.dumps(data, indent=2, default=str)
        return self._render_delta_markdown(data)

    def _build_full_data(self) -> dict[str, Any]:
        ev = self._evidence
        matrix = self._compliance_gen.generate(ev)
        total_components = sum(len(s.components) for s in ev.sboms)
        license_counter: Counter[str] = Counter()
        for sbom in ev.sboms:
            for comp in sbom.components:
                for lic in comp.licenses:
                    license_counter[lic] += 1
                if not comp.licenses:
                    license_counter["Unknown"] += 1
        severity_counts: Counter[str] = Counter()
        all_findings = []
        for scan in ev.cve_scans:
            for finding in scan.findings:
                severity_counts[finding.severity.value] += 1
                all_findings.append(finding)
        total_statements = sum(len(d.statements) for d in ev.vex_documents)
        suppressed = ev.all_suppressed_cves()
        unsuppressed = ev.unsuppressed_cves()
        slsa_by_repo: dict[str, dict[str, Any]] = {}
        for att in ev.slsa_attestations:
            slsa_by_repo[att.source_repo] = {
                "verified": att.verified, "builder_id": att.builder_id,
                "build_type": att.build_type,
                "build_timestamp": str(att.build_timestamp) if att.build_timestamp else None,
            }
        compliance_data = {
            "met": matrix.met_count, "gaps": matrix.gap_count, "total": matrix.total,
            "requirements": [{"id": r.requirement_id, "description": r.description,
                              "status": r.status.value, "evidence": r.evidence_sources,
                              "gaps": r.gaps} for r in matrix.requirements],
        }
        recommendations = self._build_recommendations(ev, matrix)
        return {
            "title": "RUNE Audit Report", "generated_at": str(ev.collected_at),
            "repos": ev.repos,
            "executive_summary": {
                "total_repos": len(ev.repos), "gates_passing": ev.gates_passing(),
                "total_cves": len(all_findings),
                "critical_cves": severity_counts.get(CVESeverity.CRITICAL.value, 0),
                "high_cves": severity_counts.get(CVESeverity.HIGH.value, 0),
                "compliance_met": matrix.met_count, "compliance_total": matrix.total,
            },
            "sbom_analysis": {
                "total_components": total_components,
                "license_breakdown": dict(license_counter.most_common()),
                "sbom_count": len(ev.sboms),
            },
            "cve_findings": {
                "total": len(all_findings), "by_severity": dict(severity_counts),
                "findings": [{"cve_id": f.cve_id, "severity": f.severity.value,
                              "cvss_score": f.cvss_score, "package": f.package_name,
                              "version": f.package_version, "fixed_version": f.fixed_version}
                             for f in all_findings],
            },
            "vex_status": {
                "total_documents": len(ev.vex_documents), "total_statements": total_statements,
                "suppressed_cves": sorted(suppressed), "unsuppressed_cves": sorted(unsuppressed),
            },
            "slsa_verification": slsa_by_repo,
            "compliance_matrix": compliance_data,
            "recommendations": recommendations,
        }

    def _build_summary_data(self) -> dict[str, Any]:
        ev = self._evidence
        matrix = self._compliance_gen.generate(ev)
        severity_counts: Counter[str] = Counter()
        for scan in ev.cve_scans:
            for finding in scan.findings:
                severity_counts[finding.severity.value] += 1
        critical_findings = []
        for scan in ev.cve_scans:
            for finding in scan.findings:
                if finding.severity in (CVESeverity.CRITICAL, CVESeverity.HIGH):
                    critical_findings.append({"cve_id": finding.cve_id,
                                              "severity": finding.severity.value,
                                              "cvss_score": finding.cvss_score,
                                              "package": finding.package_name})
        overall_status = "PASS" if ev.gates_passing() and matrix.gap_count == 0 else "NEEDS ATTENTION"
        return {
            "title": "RUNE Audit Summary", "generated_at": str(ev.collected_at),
            "overall_status": overall_status,
            "key_metrics": {
                "repos_covered": len(ev.repos), "gates_passing": ev.gates_passing(),
                "total_cves": sum(severity_counts.values()),
                "critical_cves": severity_counts.get(CVESeverity.CRITICAL.value, 0),
                "high_cves": severity_counts.get(CVESeverity.HIGH.value, 0),
                "compliance_met": matrix.met_count, "compliance_total": matrix.total,
                "slsa_verified": sum(1 for a in ev.slsa_attestations if a.verified),
            },
            "critical_findings": critical_findings,
        }

    def _build_delta_data(self, previous: EvidenceBundle) -> dict[str, Any]:
        current = self._evidence
        current_cves = current.all_cve_ids()
        previous_cves = previous.all_cve_ids()
        new_cves = sorted(current_cves - previous_cves)
        resolved_cves = sorted(previous_cves - current_cves)
        current_components: set[str] = set()
        for sbom in current.sboms:
            for comp in sbom.components:
                current_components.add(f"{comp.name}@{comp.version}")
        previous_components: set[str] = set()
        for sbom in previous.sboms:
            for comp in sbom.components:
                previous_components.add(f"{comp.name}@{comp.version}")
        new_components = sorted(current_components - previous_components)
        removed_components = sorted(previous_components - current_components)
        current_matrix = self._compliance_gen.generate(current)
        previous_matrix = self._compliance_gen.generate(previous)
        prev_status_map = {r.requirement_id: r.status.value for r in previous_matrix.requirements}
        compliance_changes = []
        for req in current_matrix.requirements:
            prev_val = prev_status_map.get(req.requirement_id, "N/A")
            if req.status.value != prev_val:
                compliance_changes.append({"requirement": req.requirement_id,
                                           "previous": prev_val, "current": req.status.value})
        return {
            "title": "RUNE Audit Delta Report",
            "generated_at": str(current.collected_at),
            "previous_collected_at": str(previous.collected_at),
            "cve_changes": {"new_cves": new_cves, "resolved_cves": resolved_cves},
            "component_changes": {"new_components": new_components,
                                  "removed_components": removed_components},
            "compliance_changes": compliance_changes,
        }

    def _build_recommendations(self, ev: EvidenceBundle, matrix: Any) -> list[str]:
        recs: list[str] = []
        for scan in ev.cve_scans:
            for finding in scan.findings:
                if finding.severity == CVESeverity.CRITICAL:
                    recs.append(f"CRITICAL: Remediate {finding.cve_id} in {finding.package_name}")
                elif finding.severity == CVESeverity.HIGH and finding.fixed_version:
                    recs.append(f"HIGH: Upgrade {finding.package_name} to {finding.fixed_version} ({finding.cve_id})")
        unsuppressed = ev.unsuppressed_cves()
        if unsuppressed:
            recs.append(f"Address {len(unsuppressed)} unsuppressed CVE(s) with VEX statements")
        if not ev.slsa_attestations:
            recs.append("Enable SLSA provenance attestations for all repositories")
        gaps = self._compliance_gen.get_gaps(matrix)
        if gaps:
            recs.append(f"Close {len(gaps)} compliance gap(s): " + ", ".join(g.requirement_id for g in gaps))
        if not recs:
            recs.append("No critical issues found -- maintain current security posture")
        return recs

    def _render_full_markdown(self, data: dict[str, Any]) -> str:
        L = []
        L.append(f"# {data['title']}")
        L.append("")
        L.append(f"Generated: {data['generated_at']}")
        L.append(f"Repositories: {', '.join(data['repos'])}")
        L.append("")
        es = data["executive_summary"]
        L.append("## Executive Summary")
        L.append("")
        L.append(f"- **Repos covered**: {es['total_repos']}")
        L.append("- **Gates passing**: " + ("Yes" if es["gates_passing"] else "No"))
        L.append(f"- **Total CVEs**: {es['total_cves']}")
        L.append(f"- **Critical CVEs**: {es['critical_cves']}")
        L.append(f"- **High CVEs**: {es['high_cves']}")
        L.append(f"- **Compliance**: {es['compliance_met']}/{es['compliance_total']} requirements met")
        L.append("")
        sb = data["sbom_analysis"]
        L.append("## SBOM Analysis")
        L.append("")
        L.append(f"- **Total components**: {sb['total_components']}")
        L.append(f"- **SBOMs collected**: {sb['sbom_count']}")
        if sb["license_breakdown"]:
            L.append("- **License breakdown**:")
            for lic, count in sb["license_breakdown"].items():
                L.append(f"  - {lic}: {count}")
        L.append("")
        cv = data["cve_findings"]
        L.append("## CVE Findings")
        L.append("")
        L.append(f"Total findings: {cv['total']}")
        if cv["by_severity"]:
            L.append("")
            L.append("| Severity | Count |")
            L.append("|---|---|")
            for sev, cnt in cv["by_severity"].items():
                L.append(f"| {sev} | {cnt} |")
        if cv["findings"]:
            L.append("")
            L.append("| CVE | Severity | CVSS | Package | Version | Fix |")
            L.append("|---|---|---|---|---|---|")
            for f in cv["findings"]:
                cs = f["cvss_score"] if f["cvss_score"] is not None else "N/A"
                fx = f["fixed_version"] or "None"
                L.append(f"| {f['cve_id']} | {f['severity']} | {cs} | {f['package']} | {f['version']} | {fx} |")
        L.append("")
        vx = data["vex_status"]
        L.append("## VEX Status")
        L.append("")
        L.append(f"- **VEX documents**: {vx['total_documents']}")
        L.append(f"- **Total statements**: {vx['total_statements']}")
        L.append(f"- **Suppressed CVEs**: {len(vx['suppressed_cves'])}")
        L.append(f"- **Unsuppressed CVEs**: {len(vx['unsuppressed_cves'])}")
        L.append("")
        sl = data["slsa_verification"]
        L.append("## SLSA Verification")
        L.append("")
        if sl:
            L.append("| Repository | Verified | Builder |")
            L.append("|---|---|---|")
            for repo, info in sl.items():
                v = "Yes" if info["verified"] else "No"
                L.append(f"| {repo} | {v} | {info['builder_id']} |")
        else:
            L.append("No SLSA attestations collected.")
        L.append("")
        cm = data["compliance_matrix"]
        L.append("## Compliance Matrix")
        L.append("")
        L.append(f"Summary: {cm['met']}/{cm['total']} requirements met")
        L.append("")
        L.append("| Requirement | Description | Status | Gaps |")
        L.append("|---|---|---|---|")
        for req in cm["requirements"]:
            gs = "; ".join(req["gaps"]) if req["gaps"] else "None"
            L.append(f"| {req['id']} | {req['description']} | **{req['status']}** | {gs} |")
        L.append("")
        L.append("## Recommendations")
        L.append("")
        for rec in data["recommendations"]:
            L.append(f"- {rec}")
        L.append("")
        return "\n".join(L)

    def _render_summary_markdown(self, data: dict[str, Any]) -> str:
        L = []
        L.append(f"# {data['title']}")
        L.append("")
        L.append(f"Generated: {data['generated_at']}")
        L.append(f"Overall status: **{data['overall_status']}**")
        L.append("")
        km = data["key_metrics"]
        L.append("## Key Metrics")
        L.append("")
        L.append(f"- **Repos covered**: {km['repos_covered']}")
        L.append("- **Gates passing**: " + ("Yes" if km["gates_passing"] else "No"))
        L.append(f"- **Total CVEs**: {km['total_cves']}")
        L.append(f"- **Critical CVEs**: {km['critical_cves']}")
        L.append(f"- **High CVEs**: {km['high_cves']}")
        L.append(f"- **Compliance**: {km['compliance_met']}/{km['compliance_total']} requirements met")
        L.append(f"- **SLSA verified**: {km['slsa_verified']}")
        L.append("")
        if data["critical_findings"]:
            L.append("## Critical Findings")
            L.append("")
            L.append("| CVE | Severity | CVSS | Package |")
            L.append("|---|---|---|---|")
            for f in data["critical_findings"]:
                cs = f["cvss_score"] if f["cvss_score"] is not None else "N/A"
                L.append(f"| {f['cve_id']} | {f['severity']} | {cs} | {f['package']} |")
            L.append("")
        return "\n".join(L)

    def _render_delta_markdown(self, data: dict[str, Any]) -> str:
        L = []
        L.append(f"# {data['title']}")
        L.append("")
        L.append(f"Generated: {data['generated_at']}")
        L.append(f"Comparing against: {data['previous_collected_at']}")
        L.append("")
        cc = data["cve_changes"]
        L.append("## CVE Changes")
        L.append("")
        if cc["new_cves"]:
            L.append("**New CVEs:**")
            for cid in cc["new_cves"]:
                L.append(f"- {cid}")
        else:
            L.append("No new CVEs.")
        L.append("")
        if cc["resolved_cves"]:
            L.append("**Resolved CVEs:**")
            for cid in cc["resolved_cves"]:
                L.append(f"- {cid}")
        else:
            L.append("No resolved CVEs.")
        L.append("")
        cp = data["component_changes"]
        L.append("## Component Changes")
        L.append("")
        if cp["new_components"]:
            L.append("**New components:**")
            for c in cp["new_components"]:
                L.append(f"- {c}")
        else:
            L.append("No new components.")
        L.append("")
        if cp["removed_components"]:
            L.append("**Removed components:**")
            for c in cp["removed_components"]:
                L.append(f"- {c}")
        else:
            L.append("No removed components.")
        L.append("")
        cch = data["compliance_changes"]
        L.append("## Compliance Changes")
        L.append("")
        if cch:
            L.append("| Requirement | Previous | Current |")
            L.append("|---|---|---|")
            for ch in cch:
                L.append(f"| {ch['requirement']} | {ch['previous']} | {ch['current']} |")
        else:
            L.append("No compliance status changes.")
        L.append("")
        return "\n".join(L)
