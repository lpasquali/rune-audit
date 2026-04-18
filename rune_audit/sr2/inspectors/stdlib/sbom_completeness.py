# SPDX-License-Identifier: Apache-2.0
"""SBOM artifact hints (rune-docs#230) — shallow heuristic."""

from __future__ import annotations

from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.inspectors.stdlib._util import any_file, na, ok
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec):
    root = ctx.root
    if any_file(root, ("**/sbom*.json", "**/*cyclonedx*.json", "**/bom.json")):
        return ok(spec, "SBOM-like JSON present")
    return na(spec, "no SBOM JSON artifacts detected")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.sbom_completeness", _inspect)
    reg.register("SR-Q-025", _inspect)
