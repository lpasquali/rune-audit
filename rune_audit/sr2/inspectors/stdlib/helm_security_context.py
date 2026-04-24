# SPDX-License-Identifier: Apache-2.0
"""Helm / K8s manifests: securityContext mentions (rune-docs#230)."""

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
    markers = {
        "SR-Q-021": ["securitycontext:"],
        "SR-Q-022": ["securitycontext:", "pod-security.kubernetes.io"],
        "SR-Q-006": ["workqueuedepth", "max-queue-depth"],
        "SR-Q-013": ["resources:", "limits:", "cpu:", "memory:"],
        "SR-Q-014": ["resourcequota", "limitrange"],
    }
    targets = markers.get(spec.id, ["securitycontext:"])

    for path in list(root.rglob("*.yaml")) + list(root.rglob("*.yml")):
        rel = path.relative_to(root).as_posix()
        if "/templates/" not in rel and not rel.startswith("charts/"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        for m in targets:
            if m in text:
                return ok(spec, f"{spec.id} requirements referenced ({rel})")
    return na(spec, f"no relevant markers found for {spec.id}")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.helm_security_context", _inspect)
    reg.register("SR-Q-006", _inspect)
    reg.register("SR-Q-013", _inspect)
    reg.register("SR-Q-014", _inspect)
    reg.register("SR-Q-021", _inspect)
    reg.register("SR-Q-022", _inspect)
