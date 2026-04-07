# SPDX-License-Identifier: Apache-2.0
"""Tests for package-level attributes."""

from __future__ import annotations


def test_version_attribute() -> None:
    """Package exposes __version__."""
    from rune_audit import __version__

    assert __version__ == "0.0.0a0"
