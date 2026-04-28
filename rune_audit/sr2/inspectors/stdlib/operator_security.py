# SPDX-License-Identifier: Apache-2.0
"""Operator security implementation inspectors (EPIC #211)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rune_audit.sr2.models import InspectResult

from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.inspectors.stdlib._util import fail, na, ok, read_text_safe
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect_operator(ctx: InspectContext, spec: RequirementSpec) -> InspectResult:
    root = ctx.root
    controller = root / "controllers" / "runebenchmark_controller.go"
    if not controller.is_file():
        # Maybe we are in the workspace root
        controller = root / "rune-operator" / "controllers" / "runebenchmark_controller.go"

    if not controller.is_file():
        return na(spec, "runebenchmark_controller.go not found")

    text = read_text_safe(controller)

    if spec.id == "SR-Q-009":
        if "TimeoutSeconds" in text and "time.Duration" in text:
            return ok(spec, "Job execution timeout implemented in operator")
        return fail(spec, "TimeoutSeconds logic not found in operator")

    return na(spec, "unsupported SR-Q ID for operator inspector")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.operator_security", _inspect_operator)
    reg.register("SR-Q-009", _inspect_operator)
