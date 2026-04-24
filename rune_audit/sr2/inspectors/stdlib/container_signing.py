# SPDX-License-Identifier: Apache-2.0
"""Container image signing hints (rune-docs#230)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rune_audit.sr2.models import InspectResult

from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.inspectors.stdlib._util import na, ok, read_text_safe
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec) -> InspectResult:
    root = ctx.root
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return na(spec, "no workflows")
    for yml in list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")):
        t = read_text_safe(yml).lower()
        if "cosign" in t or "sigstore" in t:
            return ok(spec, "cosign/sigstore referenced")
    return na(spec, "no container signing hints")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.container_signing", _inspect)
