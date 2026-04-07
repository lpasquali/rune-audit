# SPDX-License-Identifier: Apache-2.0
"""Tests for base collector protocol."""

from __future__ import annotations

from rune_audit.collectors.base import Collector


def test_collector_protocol_exists() -> None:
    """Collector protocol is importable and has collect method."""
    assert hasattr(Collector, "collect")
