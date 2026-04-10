# SPDX-License-Identifier: Apache-2.0
"""GitHub Actions action reference pinning (rune-docs#230)."""

from __future__ import annotations

import re

from rune_audit.sr2.inspector_stdlib._util import fail, na, ok, read_text_safe
from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry

_USE_LINE = re.compile(r"^\s*uses:\s*([^#]+)", re.MULTILINE)
_PINNED = re.compile(r"@([0-9a-f]{40}|v\d)")


def _inspect(ctx: InspectContext, spec: RequirementSpec):
    root = ctx.root
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return na(spec, "no .github/workflows")
    bad = False
    checked = 0
    for yml in list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")):
        text = read_text_safe(yml)
        for m in _USE_LINE.finditer(text):
            checked += 1
            ref = m.group(1).strip()
            if "docker://" in ref or "${{" in ref:
                continue
            if not _PINNED.search(ref):
                bad = True
    if checked == 0:
        return na(spec, "workflows without uses: steps")
    if bad:
        return fail(spec, "unpinned or non-hash action ref detected")
    return ok(spec, "action references look pinned")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.github_actions_pinning", _inspect)
