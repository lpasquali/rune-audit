# SPDX-License-Identifier: Apache-2.0
"""SR-2 inspectors (stubs today; replace per requirement in #211)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path  # noqa: TC003
from typing import TYPE_CHECKING

from rune_audit.sr2.models import InspectResult, InspectStatus, RequirementSpec

if TYPE_CHECKING:
    from rune_audit.sr2.registry import InspectorRegistry


@dataclass
class InspectContext:
    """Repository root and optional config."""

    root: Path


def stub_inspector(_ctx: InspectContext, spec: RequirementSpec) -> InspectResult:
    """Placeholder until automated checks exist for *spec*."""
    return InspectResult(
        requirement_id=spec.id,
        status=InspectStatus.NOT_IMPLEMENTED,
        detail="inspector not yet implemented (rune-audit#211)",
    )


def run_all(
    ctx: InspectContext,
    specs: tuple[RequirementSpec, ...],
    *,
    registry: InspectorRegistry | None = None,
) -> list[InspectResult]:
    from rune_audit.sr2.registry import default_registry

    reg = registry if registry is not None else default_registry()
    return [reg.get(s.id)(ctx, s) for s in specs]
