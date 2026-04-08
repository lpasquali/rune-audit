# SPDX-License-Identifier: Apache-2.0
"""Tests for TLA+ formal verification checker."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from rune_audit.formal.checker import TLAChecker, _extract_description, parse_tlc_output
from rune_audit.formal.models import CheckResult, SpecInfo


class TestParseTlcOutput:
    def test_successful_run(self) -> None:
        stdout = (
            "TLC2 Version 2.18\n"
            "Model checking completed. No error has been found.\n"
            "  42 states generated, 15 distinct states found.\n"
        )
        passed, states, distinct, violations = parse_tlc_output(stdout)
        assert passed is True
        assert states == 42
        assert distinct == 15
        assert violations == []

    def test_invariant_violation(self) -> None:
        stdout = (
            "TLC2 Version 2.18\n"
            "Error: Invariant SafetyInvariant is violated.\n"
            "Invariant SafetyInvariant is violated\n"
            "  10 states generated, 5 distinct states found.\n"
        )
        passed, states, distinct, violations = parse_tlc_output(stdout)
        assert passed is False
        assert states == 10
        assert distinct == 5
        assert len(violations) >= 1
        assert any("SafetyInvariant" in v for v in violations)

    def test_error_message(self) -> None:
        stdout = "Error: The specification has a syntax error.\n"
        passed, _, _, violations = parse_tlc_output(stdout)
        assert passed is False
        assert len(violations) == 1
        assert "syntax error" in violations[0]

    def test_empty_output(self) -> None:
        passed, states, distinct, violations = parse_tlc_output("")
        assert passed is False
        assert states == 0
        assert distinct == 0
        assert violations == []

    def test_no_states_line(self) -> None:
        stdout = "Model checking completed. No error has been found.\n"
        passed, states, distinct, violations = parse_tlc_output(stdout)
        assert passed is True
        assert states == 0
        assert distinct == 0

    def test_multiple_violations(self) -> None:
        stdout = (
            "Error: Invariant TypeOK is violated\n"
            "Invariant TypeOK is violated\n"
            "Error: Invariant SafetyInvariant is violated\n"
            "Invariant SafetyInvariant is violated\n"
        )
        passed, _, _, violations = parse_tlc_output(stdout)
        assert passed is False
        assert len(violations) >= 2


class TestExtractDescription:
    def test_standard_header(self, tmp_path: Path) -> None:
        spec = tmp_path / "Test.tla"
        spec.write_text(
            "---- MODULE Test ----\n(*\n"
            " * TLA+ specification for the test component.\n *)\n"
        )
        desc = _extract_description(spec)
        assert "test component" in desc

    def test_missing_file(self, tmp_path: Path) -> None:
        assert _extract_description(tmp_path / "Missing.tla") == ""

    def test_no_comment(self, tmp_path: Path) -> None:
        spec = tmp_path / "NoComment.tla"
        spec.write_text("---- MODULE NoComment ----\nEXTENDS Integers\n====\n")
        assert _extract_description(spec) == ""

    def test_fallback_description(self, tmp_path: Path) -> None:
        spec = tmp_path / "Fallback.tla"
        spec.write_text("---- MODULE Fallback ----\n(*\n * A fallback description line\n *)\n")
        assert "fallback" in _extract_description(spec).lower()


class TestTLACheckerCheck:
    def test_check_success(self, tmp_path: Path) -> None:
        spec_file = tmp_path / "Test.tla"
        spec_file.write_text("---- MODULE Test ----\n====\n")
        mock_result = MagicMock()
        mock_result.stdout = (
            "Model checking completed. No error has been found.\n"
            "  100 states generated, 50 distinct states found.\n"
        )
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            checker = TLAChecker(specs_dir=tmp_path)
            result = checker.check(spec_file)
        assert result.passed is True
        assert result.spec == "Test"
        assert result.states_found == 100
        assert result.distinct_states == 50
        assert result.violations == []
        assert result.duration_seconds >= 0
        mock_run.assert_called_once()

    def test_check_failure_violation(self, tmp_path: Path) -> None:
        spec_file = tmp_path / "Bad.tla"
        spec_file.write_text("---- MODULE Bad ----\n====\n")
        mock_result = MagicMock()
        mock_result.stdout = "Error: Invariant SafetyInvariant is violated.\nInvariant SafetyInvariant is violated\n"
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result):
            result = TLAChecker(specs_dir=tmp_path).check(spec_file)
        assert result.passed is False
        assert len(result.violations) >= 1

    def test_check_with_config(self, tmp_path: Path) -> None:
        spec_file = tmp_path / "Test.tla"
        spec_file.write_text("---- MODULE Test ----\n====\n")
        cfg_file = tmp_path / "Test.cfg"
        cfg_file.write_text("INIT Init\nNEXT Next\n")
        mock_result = MagicMock()
        mock_result.stdout = "Model checking completed. No error has been found.\n"
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = TLAChecker(specs_dir=tmp_path).check(spec_file, config_path=cfg_file)
        assert result.passed is True
        call_args = mock_run.call_args[0][0]
        assert "-config" in call_args
        assert str(cfg_file) in call_args

    def test_check_timeout(self, tmp_path: Path) -> None:
        spec_file = tmp_path / "Slow.tla"
        spec_file.write_text("---- MODULE Slow ----\n====\n")
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="java", timeout=10)):
            result = TLAChecker(specs_dir=tmp_path, timeout=10).check(spec_file)
        assert result.passed is False
        assert any("timed out" in v for v in result.violations)

    def test_check_tlc_not_found(self, tmp_path: Path) -> None:
        spec_file = tmp_path / "Test.tla"
        spec_file.write_text("---- MODULE Test ----\n====\n")
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = TLAChecker(specs_dir=tmp_path).check(spec_file)
        assert result.passed is False
        assert any("not found" in v.lower() for v in result.violations)

    def test_custom_tlc_command(self, tmp_path: Path) -> None:
        spec_file = tmp_path / "Test.tla"
        spec_file.write_text("---- MODULE Test ----\n====\n")
        mock_result = MagicMock()
        mock_result.stdout = "Model checking completed. No error has been found.\n"
        mock_result.stderr = ""
        custom_cmd = ["java", "-cp", "/opt/tla/tla2tools.jar", "tlc2.TLC"]
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            TLAChecker(specs_dir=tmp_path, tlc_command=custom_cmd).check(spec_file)
        assert mock_run.call_args[0][0][:4] == custom_cmd


class TestTLACheckerListSpecs:
    def test_list_specs(self, tmp_path: Path) -> None:
        (tmp_path / "AuditChain.tla").write_text(
            "---- MODULE AuditChain ----\n(*\n * TLA+ specification for the audit chain.\n *)\n====\n"
        )
        (tmp_path / "Gate.tla").write_text("---- MODULE Gate ----\n====\n")
        (tmp_path / "README.md").write_text("# Hello\n")
        specs = TLAChecker(specs_dir=tmp_path).list_specs()
        assert len(specs) == 2
        names = [s.name for s in specs]
        assert "AuditChain" in names
        assert "Gate" in names

    def test_list_specs_empty_dir(self, tmp_path: Path) -> None:
        assert TLAChecker(specs_dir=tmp_path).list_specs() == []

    def test_list_specs_nonexistent_dir(self, tmp_path: Path) -> None:
        assert TLAChecker(specs_dir=tmp_path / "nonexistent").list_specs() == []

    def test_list_specs_from_real_specs_dir(self) -> None:
        from rune_audit.formal.checker import DEFAULT_SPECS_DIR
        specs = TLAChecker(specs_dir=DEFAULT_SPECS_DIR).list_specs()
        names = [s.name for s in specs]
        assert "AuditChain" in names
        assert "ComplianceMatrix" in names
        assert "GateAggregation" in names


class TestModelSerialization:
    def test_check_result_serialization(self) -> None:
        result = CheckResult(
            spec="AuditChain", passed=True, states_found=42, distinct_states=15, duration_seconds=1.234,
        )
        data = result.model_dump()
        assert data["spec"] == "AuditChain"
        assert data["passed"] is True
        assert CheckResult.model_validate(data) == result

    def test_check_result_with_violations(self) -> None:
        result = CheckResult(spec="Bad", passed=False, violations=["Invariant X violated", "Invariant Y violated"])
        data = result.model_dump()
        assert len(data["violations"]) == 2
        assert CheckResult.model_validate(data).violations == result.violations

    def test_spec_info_serialization(self, tmp_path: Path) -> None:
        info = SpecInfo(name="AuditChain", path=tmp_path / "AuditChain.tla", description="Audit chain")
        data = info.model_dump()
        assert data["name"] == "AuditChain"
        restored = SpecInfo.model_validate(data)
        assert restored.name == info.name

    def test_check_result_json_roundtrip(self) -> None:
        result = CheckResult(spec="Test", passed=True, states_found=10, distinct_states=5, duration_seconds=0.5)
        assert CheckResult.model_validate_json(result.model_dump_json()) == result
