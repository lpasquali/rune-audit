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
    ni = [r for r in report.results if r.status == InspectStatus.NOT_IMPLEMENTED]
    # All 36 are now implemented
    assert len(ni) == 0


def test_exit_code_strict() -> None:
    report = run_verification(root=None, priority=None)
    assert exit_code_for(report, strict=False) == 0
    # Since there are no longer NOT_IMPLEMENTED entries, strict should be 0
    assert exit_code_for(report, strict=True) == 0


def test_summarize_counts() -> None:
    report = run_verification(root=None, priority=Priority.P0)
    s = summarize(report)
    # P0s: SR-Q-004, 005, 016, 024 are all implemented now.
    assert s.get("not_implemented") is None


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
    assert packs.ids_for_pack("slsa-l3") == frozenset({"SLSA-BUILD", "SLSA-SIGN"})


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
