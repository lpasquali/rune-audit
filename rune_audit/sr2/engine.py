# SPDX-License-Identifier: Apache-2.0
"""SR-2 verify engine."""

from __future__ import annotations

from pathlib import Path

from rune_audit.sr2.catalog import iter_requirements
from rune_audit.sr2.inspectors import InspectContext, run_all, stub_inspector
from rune_audit.sr2.models import InspectStatus, Priority, RequirementSpec, VerifyReport
from rune_audit.sr2.packs import load_builtin_pack
from rune_audit.sr2.registry import default_registry, InspectorFn


def run_pack_verification(*, root: Path, pack_stem: str) -> VerifyReport:
    """Run inspectors defined in a builtin YAML pack (non–SR-Q ids allowed)."""
    doc = load_builtin_pack(pack_stem)
    ctx_root = root.resolve()
    ctx = InspectContext(root=ctx_root)
    reg = default_registry()
    results = []
    for row in doc.requirements:
        try:
            prio = Priority(row.priority.upper())
        except ValueError:
            prio = Priority.P2
        spec = RequirementSpec(id=row.id, title=row.title, priority=prio, threshold=row.threshold)
        key = row.inspector.strip()
        fn: InspectorFn
        if key in ("builtin://stub", "builtin://") or key.startswith("builtin://stub"):
            fn = stub_inspector
        elif key.startswith("stdlib."):
            fn = reg.get(key)
        else:
            fn = reg.get(row.id)
        results.append(fn(ctx, spec))
    return VerifyReport(results=results, root=str(ctx_root))


def run_verification(
    *,
    root: Path | None,
    priority: Priority | None,
) -> VerifyReport:
    """Run all registered checks (stubs return NOT_IMPLEMENTED)."""
    specs = iter_requirements()
    if priority is not None:
        specs = tuple(s for s in specs if s.priority == priority)
    ctx_root = root.resolve() if root is not None else None
    ctx = InspectContext(root=ctx_root or Path("."))
    results = run_all(ctx, specs)
    return VerifyReport(results=results, root=str(ctx_root) if ctx_root is not None else None)


def exit_code_for(report: VerifyReport, *, strict: bool) -> int:
    """0 = all pass, 1 = any fail, 2 = not implemented (only if strict)."""
    if any(r.status == InspectStatus.FAIL for r in report.results):
        return 1
    if strict and any(r.status == InspectStatus.NOT_IMPLEMENTED for r in report.results):
        return 2
    return 0


def summarize(report: VerifyReport) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in report.results:
        key = r.status.value
        counts[key] = counts.get(key, 0) + 1
    return counts
