# SPDX-License-Identifier: Apache-2.0
"""Kubernetes NetworkPolicy manifest (rune-docs#230)."""

from __future__ import annotations

from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.inspectors.stdlib._util import na, ok, read_text_safe
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec):
    root = ctx.root
    for path in root.rglob("*.yaml"):
        try:
            if path.stat().st_size > 500_000:
                continue
        except OSError:
            continue
        text = read_text_safe(path, limit=50_000)
        if "kind:" in text and "NetworkPolicy" in text:
            return ok(spec, f"NetworkPolicy in {path.relative_to(root)}")
    for path in root.rglob("*.yml"):
        text = read_text_safe(path, limit=50_000)
        if "kind:" in text and "NetworkPolicy" in text:
            return ok(spec, f"NetworkPolicy in {path.relative_to(root)}")
    return na(spec, "no NetworkPolicy manifest found")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.network_policy_presence", _inspect)
