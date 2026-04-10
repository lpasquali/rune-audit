# SPDX-License-Identifier: Apache-2.0
"""LICENSE file presence (rune-docs#230)."""

from __future__ import annotations

from rune_audit.sr2.inspector_stdlib._util import fail, ok
from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec):
    root = ctx.root
    for name in ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"):
        p = root / name
        if p.is_file() and p.stat().st_size > 20:
            return ok(spec, f"{name} present")
    return fail(spec, "no LICENSE file at repository root")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.license_compliance", _inspect)
