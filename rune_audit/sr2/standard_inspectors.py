# SPDX-License-Identifier: Apache-2.0
"""Standard inspector entry points (EPIC #230).

Use :func:`register_inspector` here (``@register_inspector("SR-Q-00N")``) so
built-ins are collected when :func:`~rune_audit.sr2.registry.default_registry`
runs.
"""

from rune_audit.sr2.inspectors import InspectContext, stub_inspector
from rune_audit.sr2.registry import InspectorRegistry, register_inspector

__all__ = [
    "InspectContext",
    "InspectorRegistry",
    "register_inspector",
    "stub_inspector",
]
