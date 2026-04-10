# SPDX-License-Identifier: Apache-2.0
"""Pluggable inspector registry (foundation for EPIC #228)."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

from rune_audit.sr2.inspectors import stub_inspector
from rune_audit.sr2.models import InspectResult, RequirementSpec

if TYPE_CHECKING:
    from rune_audit.sr2.inspectors import InspectContext

InspectorFn = Callable[["InspectContext", RequirementSpec], InspectResult]


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
    """Registry used by the CLI until real inspectors land (#211)."""
    return InspectorRegistry()
