# SPDX-License-Identifier: Apache-2.0
"""SLSA / provenance workflow hints (rune-docs#230)."""

from __future__ import annotations

from rune_audit.sr2.inspector_stdlib._util import na, ok, read_text_safe
from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec):
    root = ctx.root
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return na(spec, "no workflows for SLSA hints")
    for yml in list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")):
        text = read_text_safe(yml)
        if "slsa" in text.lower() or "provenance" in text.lower() or "attest" in text.lower():
            return ok(spec, "SLSA/provenance keyword in workflow")
    return na(spec, "no SLSA/provenance workflow hints")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.slsa_verification", _inspect)
