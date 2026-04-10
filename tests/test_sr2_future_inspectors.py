# SPDX-License-Identifier: Apache-2.0
"""Placeholder tests for full SR-2 automation (rune-docs #211 / #215)."""

import pytest


@pytest.mark.xfail(reason="Real per-requirement inspectors not merged yet (lpasquali/rune-docs#211).", strict=False)
def test_all_sr2_inspectors_implemented() -> None:
    from rune_audit.sr2.engine import run_verification

    report = run_verification(root=None, priority=None)
    assert all(r.status.value != "not_implemented" for r in report.results)
