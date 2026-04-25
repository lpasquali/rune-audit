# SPDX-License-Identifier: Apache-2.0
"""RBAC Role manifests presence (rune-docs#230) — shallow check."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rune_audit.sr2.models import InspectResult

from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.inspectors.stdlib._util import na, ok
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec) -> InspectResult:
    root = ctx.root
    for path in root.rglob("*.yaml"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        if "kind: role" in text or "kind: clusterrole" in text:
            return ok(spec, f"Role-like manifest in {path.relative_to(root)}")
    return na(spec, "no Role manifest found")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.rbac_least_privilege", _inspect)
    reg.register("SR-Q-033", _inspect)
