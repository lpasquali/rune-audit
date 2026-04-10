# SPDX-License-Identifier: Apache-2.0
"""Engine branches and error paths for coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from rune_audit.sr2.compliance_config import load_compliance_config
from rune_audit.sr2.engine import exit_code_for, run_pack_verification, run_verification, summarize
from rune_audit.sr2.models import InspectResult, InspectStatus, Priority, VerifyReport
from rune_audit.sr2.packs import PackDocument, PackMeta, PackRequirementRow, load_builtin_pack


def test_run_verification_p0_subset() -> None:
    report = run_verification(root=None, priority=Priority.P0)
    assert len(report.results) == 4


def test_summarize_includes_not_applicable() -> None:
    report = VerifyReport(
        results=[
            InspectResult(requirement_id="x", status=InspectStatus.NOT_APPLICABLE, detail="na"),
        ],
        root=None,
    )
    assert summarize(report).get("not_applicable") == 1


def test_exit_code_strict_ignores_not_applicable() -> None:
    report = VerifyReport(
        results=[
            InspectResult(requirement_id="x", status=InspectStatus.NOT_APPLICABLE, detail="na"),
        ],
        root=None,
    )
    assert exit_code_for(report, strict=True) == 0


def test_load_compliance_rejects_scalar(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        load_compliance_config(p)


def test_load_builtin_pack_unknown() -> None:
    with pytest.raises(ValueError, match="unknown pack"):
        load_builtin_pack("nope")


def test_run_pack_iec_stub(tmp_path: Path) -> None:
    r = run_pack_verification(root=tmp_path, pack_stem="iec-62443-ml4")
    assert len(r.results) == 2
    assert all(x.status == InspectStatus.NOT_IMPLEMENTED for x in r.results)


def test_run_pack_invalid_priority_defaults_to_p2(tmp_path: Path, monkeypatch) -> None:
    fake = PackDocument(
        pack=PackMeta(name="t", standard="x"),
        requirements=[
            PackRequirementRow(
                id="stdlib.license_compliance",
                title="L",
                priority="not-a-valid-priority",
                inspector="stdlib.license_compliance",
            ),
        ],
    )
    monkeypatch.setattr("rune_audit.sr2.engine.load_builtin_pack", lambda _stem: fake)
    (tmp_path / "LICENSE").write_text("Apache-2.0\n" + ("z" * 40), encoding="utf-8")
    r = run_pack_verification(root=tmp_path, pack_stem="slsa-l3")
    assert len(r.results) == 1
    assert r.results[0].status == InspectStatus.PASS


def test_run_pack_non_stdlib_inspector_uses_row_id_lookup(tmp_path: Path, monkeypatch) -> None:
    fake = PackDocument(
        pack=PackMeta(name="t", standard="x"),
        requirements=[
            PackRequirementRow(
                id="UNREGISTERED-PACK-ROW",
                title="t",
                priority="P2",
                inspector="vendor://probe",
            ),
        ],
    )
    monkeypatch.setattr("rune_audit.sr2.engine.load_builtin_pack", lambda _stem: fake)
    r = run_pack_verification(root=tmp_path, pack_stem="slsa-l3")
    assert len(r.results) == 1
    assert r.results[0].status == InspectStatus.NOT_IMPLEMENTED


def test_inspector_decorator_registers() -> None:
    from rune_audit.sr2.inspectors import InspectContext
    from rune_audit.sr2.models import RequirementSpec
    from rune_audit.sr2.registry import default_registry, inspector, reset_registry_for_tests

    reset_registry_for_tests()

    def _fn(ctx: InspectContext, spec: RequirementSpec) -> InspectResult:
        return InspectResult(requirement_id=spec.id, status=InspectStatus.PASS, detail="x")

    inspector("ZZZ-CUSTOM")(_fn)
    reg = default_registry()
    assert "ZZZ-CUSTOM" in set(reg.registered_ids())
    ctx = InspectContext(root=Path("."))
    sp = RequirementSpec(id="ZZZ-CUSTOM", title="t", priority=Priority.P2)
    assert reg.get("ZZZ-CUSTOM")(ctx, sp).status == InspectStatus.PASS
