# SPDX-License-Identifier: Apache-2.0
"""Standard inspector entry points (EPIC #230) — re-export registry helpers."""

from rune_audit.sr2.inspectors import InspectContext, stub_inspector
from rune_audit.sr2.registry import InspectorRegistry, default_registry, inspector

__all__ = [
    "InspectContext",
    "InspectorRegistry",
    "default_registry",
    "inspector",
    "stub_inspector",
]
