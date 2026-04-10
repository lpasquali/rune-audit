# SPDX-License-Identifier: Apache-2.0
"""Go module / coverage hints (rune-docs#230)."""

from __future__ import annotations

from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.inspectors.stdlib._util import any_file, na, ok
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec):
    root = ctx.root
    if not (root / "go.mod").is_file():
        return na(spec, "go.mod not present")
    if any_file(root, ("**/*_test.go",)):
        return ok(spec, "Go tests present")
    return na(spec, "go module without *_test.go")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.go_coverage", _inspect)
