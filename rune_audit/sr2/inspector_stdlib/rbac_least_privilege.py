# SPDX-License-Identifier: Apache-2.0
"""RBAC Role manifests presence (rune-docs#230) — shallow check."""

from __future__ import annotations

from rune_audit.sr2.inspector_stdlib._util import na, ok, read_text_safe
from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec):
    root = ctx.root
    for path in list(root.rglob("*.yaml")) + list(root.rglob("*.yml")):
        try:
            if path.stat().st_size > 500_000:
                continue
        except OSError:
            continue
        text = read_text_safe(path, limit=50_000)
        if "kind:" not in text:
            continue
        if "Role" in text and "apiVersion:" in text:
            return ok(spec, f"Role-like manifest in {path.relative_to(root)}")
    return na(spec, "no Role manifest found")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.rbac_least_privilege", _inspect)
