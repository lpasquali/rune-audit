# SPDX-License-Identifier: Apache-2.0
"""Static analysis in CI (rune-docs#230)."""

from __future__ import annotations

from rune_audit.sr2.inspector_stdlib._util import na, ok, read_text_safe
from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec):
    root = ctx.root
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return na(spec, "no workflows")
    for yml in list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")):
        t = read_text_safe(yml).lower()
        if "codeql" in t or "semgrep" in t or "bandit" in t or "sast" in t:
            return ok(spec, "SAST tool referenced in workflow")
    return na(spec, "no SAST workflow hints")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.sast_coverage", _inspect)
