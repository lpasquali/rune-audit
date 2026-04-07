# SPDX-License-Identifier: Apache-2.0
"""IEC 62443 ML4 compliance evidence matrix generator.

Maps evidence artifacts to IEC 62443-4-1 ML4 requirements and generates
auditable compliance matrices in Markdown, HTML, and JSON formats.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from rune_audit.models.gate import GateStatus

if TYPE_CHECKING:
    from rune_audit.models.evidence import EvidenceBundle


class ComplianceStatus(str, Enum):
    """Status of a compliance requirement."""

    MET = "Met"
    PARTIALLY_MET = "Partially Met"
    NOT_MET = "Not Met"
    NOT_APPLICABLE = "Not Applicable"


class RequirementEvidence(BaseModel):
    """Evidence mapping for a single IEC 62443 requirement."""

    requirement_id: str = Field(description="IEC 62443 requirement ID (e.g. SM-2)")
    description: str = Field(description="Requirement description")
    status: ComplianceStatus = Field(description="Current compliance status")
    evidence_sources: list[str] = Field(default_factory=list, description="Links/refs to evidence artifacts")
    last_verified: datetime | None = Field(default=None, description="When evidence was last verified")
    gaps: list[str] = Field(default_factory=list, description="Missing evidence or gaps")


class ComplianceMatrix(BaseModel):
    """Full IEC 62443-4-1 ML4 compliance evidence matrix."""

    generated_at: datetime = Field(default_factory=datetime.utcnow, description="Generation timestamp")
    requirements: list[RequirementEvidence] = Field(default_factory=list, description="Requirement mappings")
    repos_covered: list[str] = Field(default_factory=list, description="Repositories included")

    @property
    def met_count(self) -> int:
        """Count of fully met requirements."""
        return sum(1 for r in self.requirements if r.status == ComplianceStatus.MET)

    @property
    def gap_count(self) -> int:
        """Count of requirements with gaps."""
        return sum(1 for r in self.requirements if r.status == ComplianceStatus.NOT_MET)

    @property
    def total(self) -> int:
        """Total number of requirements."""
        return len(self.requirements)


IEC_62443_REQUIREMENTS: list[dict[str, str]] = [
    {"id": "SM-2", "description": "License compliance", "gate": "license", "evidence_type": "gate"},
    {"id": "SM-8", "description": "Secret scanning", "gate": "secret", "evidence_type": "gate"},
    {"id": "SM-9", "description": "SBOM provenance", "gate": "", "evidence_type": "sbom"},
    {"id": "SI-1", "description": "Static analysis (SAST)", "gate": "sast", "evidence_type": "gate"},
    {"id": "SVV-1", "description": "Verification (coverage)", "gate": "sast", "evidence_type": "gate"},
    {"id": "DM-4", "description": "Vulnerability handling (CVE+VEX)", "gate": "", "evidence_type": "vex"},
]


class ComplianceMatrixGenerator:
    """Generate IEC 62443-4-1 ML4 compliance evidence matrix."""

    def generate(self, evidence: EvidenceBundle) -> ComplianceMatrix:
        """Map evidence artifacts to IEC 62443 requirements."""
        requirements: list[RequirementEvidence] = []
        for req_def in IEC_62443_REQUIREMENTS:
            evidence_type = req_def["evidence_type"]
            if evidence_type == "gate":
                req_evidence = self._evaluate_gate_requirement(req_def, evidence)
            elif evidence_type == "sbom":
                req_evidence = self._evaluate_sbom_requirement(req_def, evidence)
            elif evidence_type == "vex":
                req_evidence = self._evaluate_vex_requirement(req_def, evidence)
            else:
                req_evidence = RequirementEvidence(
                    requirement_id=req_def["id"],
                    description=req_def["description"],
                    status=ComplianceStatus.NOT_MET,
                    gaps=[f"Unknown evidence type: {evidence_type}"],
                )
            requirements.append(req_evidence)
        return ComplianceMatrix(requirements=requirements, repos_covered=list(evidence.repos))

    def _evaluate_gate_requirement(self, req_def: dict[str, str], evidence: EvidenceBundle) -> RequirementEvidence:
        req_id = req_def["id"]
        gate_name_pattern = req_def["gate"].lower()
        matching_gates = [g for g in evidence.gate_results if gate_name_pattern in g.gate_name.lower()]
        if not matching_gates:
            return RequirementEvidence(
                requirement_id=req_id,
                description=req_def["description"],
                status=ComplianceStatus.NOT_MET,
                gaps=[f"No gate results found matching '{gate_name_pattern}'"],
            )
        passing = [g for g in matching_gates if g.status == GateStatus.PASS]
        failing = [g for g in matching_gates if g.status == GateStatus.FAIL]
        evidence_sources = [f"{g.source_repo}: {g.gate_name} ({g.status.value})" for g in matching_gates]
        latest_ts = max((g.timestamp for g in matching_gates if g.timestamp is not None), default=None)
        if failing:
            status = ComplianceStatus.NOT_MET
            gaps = [f"Gate failing in: {', '.join(g.source_repo for g in failing)}"]
        elif len(passing) < len(evidence.repos):
            status = ComplianceStatus.PARTIALLY_MET
            covered_repos = {g.source_repo for g in passing}
            missing = [r for r in evidence.repos if r not in covered_repos]
            gaps = [f"Missing gate results from: {', '.join(missing)}"]
        else:
            status = ComplianceStatus.MET
            gaps = []
        return RequirementEvidence(
            requirement_id=req_id,
            description=req_def["description"],
            status=status,
            evidence_sources=evidence_sources,
            last_verified=latest_ts,
            gaps=gaps,
        )

    def _evaluate_sbom_requirement(self, req_def: dict[str, str], evidence: EvidenceBundle) -> RequirementEvidence:
        req_id = req_def["id"]
        if not evidence.sboms:
            return RequirementEvidence(
                requirement_id=req_id,
                description=req_def["description"],
                status=ComplianceStatus.NOT_MET,
                gaps=["No SBOMs collected"],
            )
        evidence_sources = []
        for sbom in evidence.sboms:
            tool_info = f" (via {sbom.tools[0].name})" if sbom.tools else ""
            evidence_sources.append(f"{sbom.source_repo}: {len(sbom.components)} components{tool_info}")
        covered_repos = {s.source_repo for s in evidence.sboms}
        missing = [r for r in evidence.repos if r not in covered_repos]
        latest_ts = max((s.timestamp for s in evidence.sboms if s.timestamp is not None), default=None)
        if missing:
            status = ComplianceStatus.PARTIALLY_MET
            gaps = [f"Missing SBOMs from: {', '.join(missing)}"]
        else:
            status = ComplianceStatus.MET
            gaps = []
        if not evidence.slsa_attestations:
            if status == ComplianceStatus.MET:
                status = ComplianceStatus.PARTIALLY_MET
            gaps.append("No SLSA attestations found for provenance verification")
        return RequirementEvidence(
            requirement_id=req_id,
            description=req_def["description"],
            status=status,
            evidence_sources=evidence_sources,
            last_verified=latest_ts,
            gaps=gaps,
        )

    def _evaluate_vex_requirement(self, req_def: dict[str, str], evidence: EvidenceBundle) -> RequirementEvidence:
        req_id = req_def["id"]
        if not evidence.cve_scans and not evidence.vex_documents:
            return RequirementEvidence(
                requirement_id=req_id,
                description=req_def["description"],
                status=ComplianceStatus.NOT_MET,
                gaps=["No CVE scans or VEX documents collected"],
            )
        evidence_sources: list[str] = []
        gaps: list[str] = []
        if evidence.cve_scans:
            total_findings = sum(len(s.findings) for s in evidence.cve_scans)
            evidence_sources.append(f"{len(evidence.cve_scans)} scan(s) with {total_findings} finding(s)")
        else:
            gaps.append("No CVE scan results available")
        if evidence.vex_documents:
            total_stmts = sum(len(d.statements) for d in evidence.vex_documents)
            evidence_sources.append(f"{len(evidence.vex_documents)} VEX doc(s) with {total_stmts} statement(s)")
        else:
            gaps.append("No VEX documents available")
        unsuppressed = evidence.unsuppressed_cves()
        if unsuppressed:
            gaps.append(f"{len(unsuppressed)} CVE(s) not addressed by VEX: {', '.join(sorted(unsuppressed)[:5])}")
        if gaps:
            status = ComplianceStatus.PARTIALLY_MET if evidence_sources else ComplianceStatus.NOT_MET
        else:
            status = ComplianceStatus.MET
        return RequirementEvidence(
            requirement_id=req_id,
            description=req_def["description"],
            status=status,
            evidence_sources=evidence_sources,
            gaps=gaps,
        )

    def render_markdown(self, matrix: ComplianceMatrix) -> str:
        lines: list[str] = []
        lines.append("# IEC 62443-4-1 ML4 Compliance Evidence Matrix")
        lines.append("")
        lines.append(f"Generated: {matrix.generated_at.isoformat()}")
        lines.append(f"Repositories: {', '.join(matrix.repos_covered)}")
        lines.append(f"Summary: {matrix.met_count}/{matrix.total} requirements met")
        lines.append("")
        lines.append("| Requirement | Description | Status | Evidence | Gaps |")
        lines.append("|---|---|---|---|---|")
        for req in matrix.requirements:
            evidence_str = "; ".join(req.evidence_sources) if req.evidence_sources else "None"
            gaps_str = "; ".join(req.gaps) if req.gaps else "None"
            lines.append(
                f"| {req.requirement_id} | {req.description} | **{req.status.value}** | {evidence_str} | {gaps_str} |"
            )
        lines.append("")
        return "\n".join(lines)

    def render_json(self, matrix: ComplianceMatrix) -> str:
        return matrix.model_dump_json(indent=2)

    def render_html(self, matrix: ComplianceMatrix) -> str:
        rows: list[str] = []
        rows.append("<table>")
        rows.append("<thead><tr>")
        rows.append("<th>Requirement</th><th>Description</th><th>Status</th><th>Evidence</th><th>Gaps</th>")
        rows.append("</tr></thead>")
        rows.append("<tbody>")
        for req in matrix.requirements:
            evidence_str = "<br>".join(req.evidence_sources) if req.evidence_sources else "None"
            gaps_str = "<br>".join(req.gaps) if req.gaps else "None"
            status_map = {
                "Met": "met",
                "Partially Met": "partial",
                "Not Met": "not-met",
                "Not Applicable": "na",
            }
            status_class = status_map.get(req.status.value, "unknown")
            rows.append("<tr>")
            rows.append(f"<td>{req.requirement_id}</td>")
            rows.append(f"<td>{req.description}</td>")
            rows.append(f'<td class="{status_class}"><strong>{req.status.value}</strong></td>')
            rows.append(f"<td>{evidence_str}</td>")
            rows.append(f"<td>{gaps_str}</td>")
            rows.append("</tr>")
        rows.append("</tbody>")
        rows.append("</table>")
        return "\n".join(rows)

    def get_gaps(self, matrix: ComplianceMatrix) -> list[RequirementEvidence]:
        return [r for r in matrix.requirements if r.status != ComplianceStatus.MET]
