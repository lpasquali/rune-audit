# SPDX-License-Identifier: Apache-2.0
"""Catalog of SR-Q requirements (1–36) with priorities."""

from __future__ import annotations

from rune_audit.sr2.models import Priority, RequirementSpec

# Titles and Priorities aligned with rune-docs/docs/architecture/QUANTITATIVE_SECURITY_REQUIREMENTS.md
_REQUIREMENTS: dict[str, tuple[str, Priority]] = {
    "SR-Q-001": ("API Token Entropy", Priority.P2),
    "SR-Q-002": ("Authentication Rate Limiting", Priority.P2),
    "SR-Q-003": ("Session Token Lifetime", Priority.P2),
    "SR-Q-004": ("API Request Body Size Limit", Priority.P0),
    "SR-Q-005": ("API Request Rate Limiting (Per Client)", Priority.P0),
    "SR-Q-006": ("Operator Work Queue Depth Limit", Priority.P2),
    "SR-Q-007": ("Database Connection Pool Limits", Priority.P2),
    "SR-Q-008": ("HTTP Server Request Timeout", Priority.P1),
    "SR-Q-009": ("Job Execution Timeout", Priority.P1),
    "SR-Q-010": ("Ollama Warmup Timeout", Priority.P2),
    "SR-Q-011": ("Driver Invocation Timeout", Priority.P1),
    "SR-Q-012": ("Vast.ai Polling Timeout", Priority.P2),
    "SR-Q-013": ("Container Resource Limits", Priority.P2),
    "SR-Q-014": ("Kubernetes Resource Quotas", Priority.P2),
    "SR-Q-015": ("TLS Minimum Version", Priority.P2),
    "SR-Q-016": ("Password/Secret Minimum Length", Priority.P0),
    "SR-Q-017": ("Unit Test Coverage Thresholds", Priority.P2),
    "SR-Q-018": ("Fuzz Test Coverage Thresholds", Priority.P2),
    "SR-Q-019": ("CVE Severity Threshold", Priority.P2),
    "SR-Q-020": ("Dependency Update Frequency", Priority.P2),
    "SR-Q-021": ("Security Context - Containers", Priority.P2),
    "SR-Q-022": ("Pod Security Standards", Priority.P2),
    "SR-Q-023": ("Audit Log Retention", Priority.P1),
    "SR-Q-024": ("Audit Trail Completeness", Priority.P0),
    "SR-Q-025": ("SBOM Component Completeness", Priority.P2),
    "SR-Q-026": ("SLSA Provenance Attestation", Priority.P2),
    "SR-Q-027": ("GitHub Actions Pinning", Priority.P2),
    "SR-Q-028": ("Network Policy - Ingress", Priority.P2),
    "SR-Q-029": ("Network Policy - Egress", Priority.P2),
    "SR-Q-030": ("Cost Estimation Confidence Threshold", Priority.P2),
    "SR-Q-031": ("Vast.ai Cost Ceiling", Priority.P2),
    "SR-Q-032": ("Health Check Endpoint Timeout", Priority.P2),
    "SR-Q-033": ("Graceful Shutdown Timeout", Priority.P2),
    "SR-Q-034": ("JSON Schema Validation", Priority.P2),
    "SR-Q-035": ("String Length Limits", Priority.P1),
    "SR-Q-036": ("Thread Pool Size Limits", Priority.P2),
}


def iter_requirements() -> tuple[RequirementSpec, ...]:
    """Yield all 36 SR-Q requirements."""
    return tuple(
        RequirementSpec(
            id=qid,
            title=title,
            priority=prio,
        )
        for qid, (title, prio) in _REQUIREMENTS.items()
    )


__all__ = ["iter_requirements"]
