# SPDX-License-Identifier: Apache-2.0
"""Placeholder for full SR-2 automation (rune-docs #211 / #215).

Previously marked xfail, the body still ran ``run_verification`` on every CI
pass (expensive for no signal). Skip until inspectors land; keep the body for
when the skip is removed.
"""

import pytest


def test_all_sr2_inspectors_implemented() -> None:
    from rune_audit.sr2.engine import run_verification

    report = run_verification(root=None, priority=None)
    assert all(r.status.value != "not_implemented" for r in report.results)
