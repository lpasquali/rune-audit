# SPDX-License-Identifier: Apache-2.0
"""Dockerfile USER directive (rune-docs#230)."""

from __future__ import annotations

from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.inspectors.stdlib._util import fail, na, ok, threshold_int
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec):
    root = ctx.root
    dockerfiles = list(root.glob("Dockerfile")) + list(root.glob("**/Dockerfile"))
    if not dockerfiles:
        return na(spec, "no Dockerfile")
    limit = threshold_int(spec, "max_dockerfiles_to_scan", 5)
    if limit < 1:
        limit = 1
    for df in dockerfiles[:limit]:
        try:
            lines = df.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        if any(line.strip().upper().startswith("USER ") for line in lines if line.strip()):
            return ok(spec, f"USER set in {df.relative_to(root)}")
    return fail(spec, f"Dockerfile without USER directive (first {limit} checked)")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.dockerfile_security", _inspect)
