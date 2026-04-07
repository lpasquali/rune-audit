# SPDX-License-Identifier: Apache-2.0
"""Unified evidence bundle that aggregates all evidence types.

The EvidenceBundle is the central data structure consumed by the compliance
matrix generator, report renderers, and signing engine.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from rune_audit.models.attestation import AttestationResult
from rune_audit.models.cve import CVEScanResult
from rune_audit.models.gate import GateResult, GateStatus
from rune_audit.models.sbom import SBOMDocument
from rune_audit.models.slsa import SLSAAttestation
from rune_audit.models.vex import VEXDocument


class EvidenceBundle(BaseModel):
    """Aggregated compliance evidence from all sources."""

    collected_at: datetime = Field(default_factory=datetime.utcnow, description="Collection timestamp")
    sboms: list[SBOMDocument] = Field(default_factory=list, description="SBOM documents")
    cve_scans: list[CVEScanResult] = Field(default_factory=list, description="CVE scan results")
    slsa_attestations: list[SLSAAttestation] = Field(default_factory=list, description="SLSA attestations")
    vex_documents: list[VEXDocument] = Field(default_factory=list, description="VEX documents")
    gate_results: list[GateResult] = Field(default_factory=list, description="Quality gate results")
    attestation_results: list[AttestationResult] = Field(default_factory=list, description="TPM2 attestation results")
    repos: list[str] = Field(default_factory=list, description="Repositories covered")

    def all_cve_ids(self) -> set[str]:
        """Return all unique CVE IDs across all scans."""
        ids: set[str] = set()
        for scan in self.cve_scans:
            for finding in scan.findings:
                ids.add(finding.cve_id)
        return ids

    def all_suppressed_cves(self) -> set[str]:
        """Return all CVE IDs suppressed by VEX documents."""
        suppressed: set[str] = set()
        for vex_doc in self.vex_documents:
            suppressed |= vex_doc.get_suppressed_cves()
        return suppressed

    def unsuppressed_cves(self) -> set[str]:
        """Return CVE IDs found in scans but not suppressed by VEX."""
        return self.all_cve_ids() - self.all_suppressed_cves()

    def gates_passing(self) -> bool:
        """Return True if all gate results are passing."""
        return all(g.status == GateStatus.PASS for g in self.gate_results)
