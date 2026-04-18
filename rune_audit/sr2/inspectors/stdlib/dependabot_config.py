# SPDX-License-Identifier: Apache-2.0
"""Dependabot configuration file (rune-docs#230)."""

from __future__ import annotations

from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.inspectors.stdlib._util import na, ok
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec):
    root = ctx.root
    candidates = [
        root / ".github" / "dependabot.yml",
        root / ".github" / "dependabot.yaml",
    ]
    if any(p.is_file() for p in candidates):
        return ok(spec, "dependabot config present")
    return na(spec, "no .github/dependabot.yml")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.dependabot_config", _inspect)
    reg.register("SR-Q-020", _inspect)
