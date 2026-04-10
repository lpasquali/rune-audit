# SPDX-License-Identifier: Apache-2.0
"""LICENSE file presence (rune-docs#230)."""

from __future__ import annotations

from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.inspectors.stdlib._util import fail, ok, threshold_int
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec):
    root = ctx.root
    min_bytes = threshold_int(spec, "min_license_bytes", 21)
    if min_bytes < 1:
        min_bytes = 1
    for name in ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"):
        p = root / name
        if p.is_file() and p.stat().st_size >= min_bytes:
            return ok(spec, f"{name} present")
    return fail(spec, "no LICENSE file at repository root")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.license_compliance", _inspect)
