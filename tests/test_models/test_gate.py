"""Tests for quality gate result models."""

from rune_audit.models.gate import GateResult, GateStatus


def test_gate_status_values():
    assert GateStatus.PASS.value == "pass"
    assert GateStatus.FAIL.value == "fail"
    assert GateStatus.SKIP.value == "skip"
    assert GateStatus.PENDING.value == "pending"


def test_from_github_job_success():
    job = {"id": 1, "name": "sec", "conclusion": "success", "completed_at": "2026-04-01T00:00:00Z", "html_url": "u"}
    g = GateResult.from_github_job(job, source_repo="r", workflow_run_id=1, workflow_name="QG")
    assert g.status == GateStatus.PASS and g.job_id == 1 and g.timestamp is not None


def test_from_github_job_failure():
    assert GateResult.from_github_job({"id": 2, "name": "s", "conclusion": "failure"}).status == GateStatus.FAIL


def test_from_github_job_skipped():
    assert GateResult.from_github_job({"id": 3, "name": "s", "conclusion": "skipped"}).status == GateStatus.SKIP


def test_from_github_job_cancelled():
    assert GateResult.from_github_job({"id": 4, "name": "s", "conclusion": "cancelled"}).status == GateStatus.SKIP


def test_from_github_job_pending():
    assert GateResult.from_github_job({"id": 5, "name": "s", "conclusion": None}).status == GateStatus.PENDING


def test_defaults():
    g = GateResult(gate_name="t", status=GateStatus.PASS)
    assert g.workflow_run_id == 0 and g.job_id == 0 and g.timestamp is None
