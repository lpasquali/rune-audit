# SPDX-License-Identifier: Apache-2.0
"""Catalog of SR-Q requirements (1–36) with priorities."""

from __future__ import annotations

from rune_audit.sr2.models import Priority, RequirementSpec

# Priorities aligned with rune-docs/docs/architecture/QUANTITATIVE_SECURITY_REQUIREMENTS.md
_PRIORITY_OVERRIDES: dict[str, Priority] = {
    "SR-Q-004": Priority.P0,
    "SR-Q-005": Priority.P0,
    "SR-Q-016": Priority.P0,
    "SR-Q-024": Priority.P0,
    "SR-Q-008": Priority.P1,
    "SR-Q-009": Priority.P1,
    "SR-Q-011": Priority.P1,
    "SR-Q-023": Priority.P1,
    "SR-Q-035": Priority.P1,
    "SR-Q-003": Priority.P2,
    "SR-Q-006": Priority.P2,
    "SR-Q-036": Priority.P2,
}


def iter_requirements() -> tuple[RequirementSpec, ...]:
    """Yield all 36 SR-Q requirements."""
    return tuple(
        RequirementSpec(
            id=f"SR-Q-{i:03d}",
            title=f"SR-Q-{i:03d} (see QUANTITATIVE_SECURITY_REQUIREMENTS.md)",
            priority=_PRIORITY_OVERRIDES.get(f"SR-Q-{i:03d}", Priority.P2),
        )
        for i in range(1, 37)
    )


__all__ = ["iter_requirements"]
