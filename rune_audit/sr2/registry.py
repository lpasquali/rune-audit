# SPDX-License-Identifier: Apache-2.0
"""Pluggable inspector registry (EPIC #228)."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

from rune_audit.sr2.inspectors import stub_inspector
from rune_audit.sr2.models import InspectResult, RequirementSpec

if TYPE_CHECKING:
    from rune_audit.sr2.inspectors import InspectContext

InspectorFn = Callable[["InspectContext", RequirementSpec], InspectResult]

_BUILTIN_INSPECTORS: list[tuple[str, InspectorFn]] = []


def register_inspector(requirement_id: str) -> Callable[[InspectorFn], InspectorFn]:
    """Decorator to register a built-in inspector (runs at import time).

    Register modules under ``rune_audit.sr2`` (or import them before
    :func:`default_registry` is called) so decorators execute and populate
    ``_BUILTIN_INSPECTORS``.
    """

    def decorator(fn: InspectorFn) -> InspectorFn:
        _BUILTIN_INSPECTORS.append((requirement_id, fn))
        return fn

    return decorator


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


def default_registry() -> InspectorRegistry:
    """Registry used by the CLI: built-ins from decorators + empty shell.

    Imports :mod:`rune_audit.sr2.standard_inspectors` for side effects (future
    ``@register_inspector`` entries).
    """
    import rune_audit.sr2.standard_inspectors  # noqa: F401

    reg = InspectorRegistry()
    for rid, fn in _BUILTIN_INSPECTORS:
        reg.register(rid, fn)
    return reg
