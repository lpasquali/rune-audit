# SPDX-License-Identifier: Apache-2.0
import pytest

from rune_audit.sr2.catalog import iter_requirements
from rune_audit.sr2.engine import exit_code_for, run_verification, summarize
from rune_audit.sr2.models import InspectStatus, Priority
from rune_audit.sr2.project_config import AuditProjectFile, default_project_template, load_project_file


def test_iter_requirements_has_36_entries() -> None:
    reqs = iter_requirements()
    assert len(reqs) == 36
    assert reqs[0].id == "SR-Q-001"
    assert reqs[-1].id == "SR-Q-036"


def test_p0_overrides() -> None:
    p0 = {r.id for r in iter_requirements() if r.priority == Priority.P0}
    assert p0 == {"SR-Q-004", "SR-Q-005", "SR-Q-016", "SR-Q-024"}


def test_run_verification_all_not_implemented() -> None:
    report = run_verification(root=None, priority=None)
    assert len(report.results) == 36
    assert all(r.status == InspectStatus.NOT_IMPLEMENTED for r in report.results)


def test_exit_code_strict() -> None:
    report = run_verification(root=None, priority=None)
    assert exit_code_for(report, strict=False) == 0
    assert exit_code_for(report, strict=True) == 2


def test_summarize_counts() -> None:
    report = run_verification(root=None, priority=Priority.P0)
    s = summarize(report)
    assert s.get("not_implemented") == 4


def test_project_file_roundtrip(tmp_path) -> None:
    p = tmp_path / "proj.yaml"
    p.write_text(default_project_template(), encoding="utf-8")
    loaded = load_project_file(p)
    assert isinstance(loaded, AuditProjectFile)
    assert loaded.version == 1


def test_project_file_rejects_non_mapping(tmp_path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("- not: a mapping\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        load_project_file(p)


def test_exit_code_on_failure() -> None:
    from rune_audit.sr2.models import InspectResult, InspectStatus, VerifyReport

    report = VerifyReport(
        results=[
            InspectResult(requirement_id="SR-Q-001", status=InspectStatus.FAIL, detail="unit test"),
        ],
        root=None,
    )
    assert exit_code_for(report, strict=False) == 1


def test_packs_ids_for_pack() -> None:
    from rune_audit.sr2 import packs

    assert packs.ids_for_pack("custom") == packs.IEC_62443_SR2


def test_registry_register(tmp_path) -> None:
    from pathlib import Path

    from rune_audit.sr2.inspectors import InspectContext
    from rune_audit.sr2.models import InspectResult, InspectStatus, RequirementSpec
    from rune_audit.sr2.registry import InspectorRegistry

    reg = InspectorRegistry()

    def always_pass(_ctx: InspectContext, spec: RequirementSpec) -> InspectResult:
        return InspectResult(requirement_id=spec.id, status=InspectStatus.PASS, detail="ok")

    reg.register("SR-Q-001", always_pass)
    ctx = InspectContext(root=Path(tmp_path))
    spec = RequirementSpec(id="SR-Q-001", title="t", priority=Priority.P2)
    assert reg.get("SR-Q-001")(ctx, spec).status == InspectStatus.PASS
    other = RequirementSpec(id="SR-Q-999", title="t", priority=Priority.P2)
    assert reg.get("SR-Q-999")(ctx, other).status == InspectStatus.NOT_IMPLEMENTED
    assert "SR-Q-001" in list(reg.registered_ids())


def test_standard_inspectors_reexport() -> None:
    import rune_audit.sr2.standard_inspectors as si

    assert si.stub_inspector is not None
    assert si.register_inspector is not None


def test_register_inspector_decorator(monkeypatch, tmp_path) -> None:
    from pathlib import Path

    import rune_audit.sr2.registry as reg_mod
    from rune_audit.sr2.inspectors import InspectContext
    from rune_audit.sr2.models import InspectResult, InspectStatus, RequirementSpec

    monkeypatch.setattr(reg_mod, "_BUILTIN_INSPECTORS", [])

    @reg_mod.register_inspector("SR-Q-036")
    def _bump(_ctx, spec: RequirementSpec) -> InspectResult:
        return InspectResult(requirement_id=spec.id, status=InspectStatus.PASS, detail="decorator-test")

    r = reg_mod.default_registry()
    ctx = InspectContext(root=Path(tmp_path))
    spec = RequirementSpec(id="SR-Q-036", title="t", priority=Priority.P2)
    assert r.get("SR-Q-036")(ctx, spec).status == InspectStatus.PASS


def test_run_verification_with_custom_registry(tmp_path) -> None:
    from pathlib import Path

    from rune_audit.sr2.models import InspectResult, InspectStatus, RequirementSpec
    from rune_audit.sr2.registry import InspectorRegistry

    reg = InspectorRegistry()

    def always_pass(_ctx, spec: RequirementSpec) -> InspectResult:
        return InspectResult(requirement_id=spec.id, status=InspectStatus.PASS, detail="custom")

    reg.register("SR-Q-001", always_pass)
    report = run_verification(root=Path(tmp_path), priority=None, registry=reg)
    by_id = {r.requirement_id: r for r in report.results}
    assert by_id["SR-Q-001"].status == InspectStatus.PASS
    assert by_id["SR-Q-002"].status == InspectStatus.NOT_IMPLEMENTED
