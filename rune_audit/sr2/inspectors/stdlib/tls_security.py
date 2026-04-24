# SPDX-License-Identifier: Apache-2.0
"""TLS minimum version enforcement (SR-Q-015)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rune_audit.sr2.models import InspectResult

from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.inspectors.stdlib._util import na, ok
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec) -> InspectResult:
    root = ctx.root
    targets = ["tls1.2", "tls1.3", "tls_1_2", "tls_1_3", "min_version=ssl.tls_1_2"]

    for path in list(root.rglob("*.yaml")) + list(root.rglob("*.yml")) + list(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        if "/.venv/" in rel or "/__pycache__/" in rel:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        for m in targets:
            if m in text:
                return ok(spec, f"TLS 1.2+ minimum version referenced ({rel})")
    return na(spec, "no explicit TLS minimum version detected")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.tls_security", _inspect)
    reg.register("SR-Q-015", _inspect)
