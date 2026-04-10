# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for standard inspectors (rune-docs#230)."""

from __future__ import annotations

from pathlib import Path

from rune_audit.sr2.models import InspectResult, InspectStatus, RequirementSpec


def na(spec: RequirementSpec, detail: str) -> InspectResult:
    return InspectResult(requirement_id=spec.id, status=InspectStatus.NOT_APPLICABLE, detail=detail)


def ok(spec: RequirementSpec, detail: str) -> InspectResult:
    return InspectResult(requirement_id=spec.id, status=InspectStatus.PASS, detail=detail)


def fail(spec: RequirementSpec, detail: str) -> InspectResult:
    return InspectResult(requirement_id=spec.id, status=InspectStatus.FAIL, detail=detail)


def any_file(root: Path, globs: tuple[str, ...]) -> bool:
    return any(any(root.glob(pattern)) for pattern in globs)


def read_text_safe(path: Path, limit: int = 400_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def threshold_int(spec: RequirementSpec, key: str, default: int) -> int:
    """Read an integer threshold from *spec.threshold*; invalid values fall back to *default*."""
    raw = (spec.threshold or {}).get(key, default)
    if isinstance(raw, bool):
        return default
    if isinstance(raw, int):
        return raw
    try:
        return int(raw)
    except TypeError, ValueError:
        return default
