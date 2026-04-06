"""Tests for quality gate result models."""

from __future__ import annotations

from rune_audit.models.gate import GateResult, GateStatus


def test_gate_status_values() -> None:
    """GateStatus has expected enum values."""
    assert GateStatus.PASS.value == "pass"
    assert GateStatus.FAIL.value == "fail"
    assert GateStatus.SKIP.value == "skip"
    assert GateStatus.ERROR.value == "error"


def test_gate_result_creation() -> None:
    """GateResult can be created with all fields."""
    result = GateResult(
        gate_name="RuneGate/Coverage/Python",
        status=GateStatus.PASS,
        message="Coverage 98%",
        job_url="https://github.com/lpasquali/rune/actions/runs/123",
    )
    assert result.gate_name == "RuneGate/Coverage/Python"
    assert result.status == GateStatus.PASS
    assert result.message == "Coverage 98%"
    assert result.job_url != ""


def test_gate_result_defaults() -> None:
    """GateResult defaults are empty strings."""
    result = GateResult(gate_name="test", status=GateStatus.SKIP)
    assert result.message == ""
    assert result.job_url == ""
