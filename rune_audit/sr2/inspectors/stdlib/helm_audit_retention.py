# SPDX-License-Identifier: Apache-2.0
"""Helm audit log retention verification (SR-Q-023)."""

from __future__ import annotations

import yaml
from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.inspectors.stdlib._util import fail, na, ok
from rune_audit.sr2.models import RequirementSpec
from rune_audit.sr2.registry import InspectorRegistry


def _inspect(ctx: InspectContext, spec: RequirementSpec):
    root = ctx.root
    # Check charts/rune/values.yaml
    values_path = root / "charts" / "rune" / "values.yaml"
    if not values_path.is_file():
        # Maybe we are in rune-charts repo
        values_path = root / "rune-charts" / "charts" / "rune" / "values.yaml"
    
    if not values_path.is_file():
        return na(spec, "rune/values.yaml not found")

    try:
        with values_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as exc:
        return fail(spec, f"failed to parse values.yaml: {exc}")

    retention = data.get("auditLogs", {}).get("retentionDays")
    if retention is None:
        return fail(spec, "auditLogs.retentionDays not set in values.yaml")
    
    if not isinstance(retention, int):
        return fail(spec, f"auditLogs.retentionDays must be an integer, got {type(retention)}")

    if retention >= 90:
        return ok(spec, f"audit log retention set to {retention} days")
    
    return fail(spec, f"audit log retention {retention} < 90 days (SR-Q-023)")


def register(reg: InspectorRegistry) -> None:
    reg.register("stdlib.helm_audit_retention", _inspect)
    reg.register("SR-Q-023", _inspect)
