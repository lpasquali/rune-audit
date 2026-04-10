# SPDX-License-Identifier: Apache-2.0
"""Pluggable inspector registry (rune-docs#228)."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

from rune_audit.sr2.inspectors import stub_inspector
from rune_audit.sr2.models import InspectResult, RequirementSpec

if TYPE_CHECKING:
    from rune_audit.sr2.inspectors import InspectContext

InspectorFn = Callable[["InspectContext", RequirementSpec], InspectResult]

_GLOBAL: InspectorRegistry | None = None
_STDLIB_REGISTERED = False


class InspectorRegistry:
    """Maps requirement ids to inspector callables."""

    def __init__(self) -> None:
        self._by_id: dict[str, InspectorFn] = {}

    def register(self, requirement_id: str, fn: InspectorFn) -> None:
        self._by_id[requirement_id] = fn

    def get(self, requirement_id: str) -> InspectorFn:
        return self._by_id.get(requirement_id, stub_inspector)

    def registered_ids(self) -> Iterator[str]:
        yield from sorted(self._by_id)


def _ensure_stdlib(reg: InspectorRegistry) -> None:
    global _STDLIB_REGISTERED
    if _STDLIB_REGISTERED:
        return
    from rune_audit.sr2.inspector_stdlib import register_stdlib_inspectors

    register_stdlib_inspectors(reg)
    _STDLIB_REGISTERED = True


def default_registry() -> InspectorRegistry:
    """Singleton registry with built-in standard inspectors loaded once."""
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = InspectorRegistry()
    _ensure_stdlib(_GLOBAL)
    return _GLOBAL


def inspector(requirement_id: str) -> Callable[[InspectorFn], InspectorFn]:
    """Decorator: register *fn* under *requirement_id* on the default registry."""

    def deco(fn: InspectorFn) -> InspectorFn:
        default_registry().register(requirement_id, fn)
        return fn

    return deco


def reset_registry_for_tests() -> None:
    """Clear singleton (tests only)."""
    global _GLOBAL, _STDLIB_REGISTERED
    _GLOBAL = None
    _STDLIB_REGISTERED = False
