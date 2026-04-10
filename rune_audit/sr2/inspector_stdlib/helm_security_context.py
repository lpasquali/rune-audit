# SPDX-License-Identifier: Apache-2.0
"""Helm / K8s manifests: securityContext mentions (rune-docs#230)."""

from __future__ import annotations

from rune_audit.sr2.inspector_stdlib._util import na, ok
from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec):
    root = ctx.root
    for path in root.rglob("*.yaml"):
        rel = path.relative_to(root).as_posix()
        if "/templates/" not in rel and not rel.startswith("charts/"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        if "securitycontext" in text:
            return ok(spec, f"securityContext referenced ({rel})")
    for path in root.rglob("*.yml"):
        rel = path.relative_to(root).as_posix()
        if "/templates/" not in rel and not rel.startswith("charts/"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        if "securitycontext" in text:
            return ok(spec, f"securityContext referenced ({rel})")
    return na(spec, "no Helm-style securityContext")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.helm_security_context", _inspect)
