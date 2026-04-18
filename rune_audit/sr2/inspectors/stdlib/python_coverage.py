# SPDX-License-Identifier: Apache-2.0
"""Python coverage configuration presence (rune-docs#230)."""

from __future__ import annotations

from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.inspectors.stdlib._util import any_file, na, ok
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec):
    root = ctx.root
    if not any_file(root, ("pyproject.toml", "setup.py", "setup.cfg")):
        return na(spec, "no Python packaging layout")
    if any_file(root, (".coveragerc",)) or _pyproject_mentions(root, "coverage"):
        return ok(spec, "coverage configuration referenced")
    return na(spec, "no coverage configuration detected")


def _pyproject_mentions(root, needle: str) -> bool:
    p = root / "pyproject.toml"
    if not p.is_file():
        return False
    try:
        return needle in p.read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return False


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.python_coverage", _inspect)
    reg.register("SR-Q-017", _inspect)
