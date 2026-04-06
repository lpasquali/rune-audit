"""Tests for all CLI command groups."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from rune_audit.cli.app import app
from rune_audit.verifiers.slsa import (
    SLSACheckResult,
    SLSARequirement,
    SLSAVerificationReport,
    VerificationStatus,
)

runner = CliRunner()


def _make_passing_report(repo: str = "rune", tag: str = "v1") -> SLSAVerificationReport:
    report = SLSAVerificationReport(repo=repo, tag=tag, attestation_found=True)
    for req in SLSARequirement:
        report.checks.append(SLSACheckResult(requirement=req, status=VerificationStatus.PASS, message="ok"))
    return report


def _make_failing_report(repo: str = "rune", tag: str = "v1") -> SLSAVerificationReport:
    report = SLSAVerificationReport(repo=repo, tag=tag, attestation_found=False)
    report.checks.append(SLSACheckResult(
        requirement=SLSARequirement.BUILD_PROVENANCE_EXISTS, status=VerificationStatus.FAIL, message="missing",
    ))
    for req in list(SLSARequirement)[1:]:
        report.checks.append(SLSACheckResult(requirement=req, status=VerificationStatus.SKIP, message="skipped"))
    return report


def _create_vex_doc(vex_dir: Path) -> None:
    vex_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.com/vex/test",
        "author": "test", "timestamp": "2026-04-06T00:00:00Z", "version": 1,
        "statements": [{"vulnerability": {"name": "CVE-2024-1234"}, "status": "not_affected",
                        "justification": "component_not_present", "products": [{"@id": "pkg:pypi/rune-audit"}]}],
    }
    (vex_dir / "test.json").write_text(json.dumps(doc))


class TestSubcommandGroups:
    def test_collect_help(self) -> None:
        result = runner.invoke(app, ["collect", "--help"])
        assert result.exit_code == 0
        assert "all" in result.output

    def test_vex_help(self) -> None:
        result = runner.invoke(app, ["vex", "--help"])
        assert result.exit_code == 0
        assert "list" in result.output

    def test_compliance_help(self) -> None:
        result = runner.invoke(app, ["compliance", "--help"])
        assert result.exit_code == 0
        assert "matrix" in result.output

    def test_slsa_help(self) -> None:
        result = runner.invoke(app, ["slsa", "--help"])
        assert result.exit_code == 0
        assert "verify" in result.output

    def test_report_help(self) -> None:
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
        assert "full" in result.output

    def test_config_help(self) -> None:
        result = runner.invoke(app, ["config", "--help"])
        assert result.exit_code == 0
        assert "show" in result.output


class TestCollectCommands:
    @patch.dict("os.environ", {"RUNE_AUDIT_GITHUB_TOKEN": ""}, clear=False)
    def test_collect_all(self) -> None:
        result = runner.invoke(app, ["collect", "all"])
        assert result.exit_code == 0
        assert "Collection complete" in result.output

    @patch.dict("os.environ", {"RUNE_AUDIT_GITHUB_TOKEN": ""}, clear=False)
    def test_collect_sbom(self) -> None:
        result = runner.invoke(app, ["collect", "sbom"])
        assert result.exit_code == 0

    @patch.dict("os.environ", {"RUNE_AUDIT_GITHUB_TOKEN": ""}, clear=False)
    def test_collect_cve(self) -> None:
        result = runner.invoke(app, ["collect", "cve"])
        assert result.exit_code == 0

    @patch.dict("os.environ", {"RUNE_AUDIT_GITHUB_TOKEN": ""}, clear=False)
    def test_collect_vex(self) -> None:
        result = runner.invoke(app, ["collect", "vex"])
        assert result.exit_code == 0


class TestVexList:
    def test_no_docs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["vex", "list", "--dir", str(Path(tmpdir) / "empty")])
            assert result.exit_code == 0

    def test_with_docs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            vex_dir = Path(tmpdir) / ".vex"
            _create_vex_doc(vex_dir)
            result = runner.invoke(app, ["vex", "list", "--dir", str(vex_dir)])
            assert result.exit_code == 0
            assert "CVE-2024-1234" in result.output


class TestVexValidate:
    def test_no_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["vex", "validate", "--dir", str(Path(tmpdir) / "nonexistent")])
            assert result.exit_code == 1

    def test_valid_doc(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            vex_dir = Path(tmpdir) / ".vex"
            _create_vex_doc(vex_dir)
            result = runner.invoke(app, ["vex", "validate", "--dir", str(vex_dir)])
            assert result.exit_code == 0
            assert "Validated 1" in result.output

    def test_invalid_doc(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            vex_dir = Path(tmpdir) / ".vex"
            vex_dir.mkdir(parents=True)
            (vex_dir / "bad.json").write_text('{"not": "valid"}')
            result = runner.invoke(app, ["vex", "validate", "--dir", str(vex_dir)])
            assert result.exit_code == 1

    def test_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            vex_dir = Path(tmpdir) / ".vex"
            vex_dir.mkdir(parents=True)
            (vex_dir / "bad.json").write_text("not json at all")
            result = runner.invoke(app, ["vex", "validate", "--dir", str(vex_dir)])
            assert result.exit_code == 1


class TestVexCrossCheck:
    def test_no_docs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["vex", "cross-check", "--dir", str(Path(tmpdir) / "empty")])
            assert result.exit_code == 0

    def test_with_docs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            vex_dir = Path(tmpdir) / ".vex"
            _create_vex_doc(vex_dir)
            result = runner.invoke(app, ["vex", "cross-check", "--dir", str(vex_dir)])
            assert result.exit_code == 0
            assert "Cross-checking" in result.output


class TestComplianceMatrix:
    def test_table_output(self) -> None:
        result = runner.invoke(app, ["compliance", "matrix"])
        assert result.exit_code == 0
        assert "SM-1" in result.output

    def test_json_output(self) -> None:
        result = runner.invoke(app, ["compliance", "matrix", "--format", "json"])
        assert result.exit_code == 0


class TestComplianceGaps:
    def test_gaps(self) -> None:
        result = runner.invoke(app, ["compliance", "gaps"])
        assert result.exit_code == 0
        assert "SI-1" in result.output


class TestSlsaVerify:
    @patch("rune_audit.cli.slsa_cmd.verify_slsa")
    def test_verify_pass(self, mock_verify: MagicMock) -> None:
        mock_verify.return_value = _make_passing_report()
        result = runner.invoke(app, ["slsa", "verify", "rune", "--tag", "v1"])
        assert result.exit_code == 0

    @patch("rune_audit.cli.slsa_cmd.verify_slsa")
    def test_verify_fail(self, mock_verify: MagicMock) -> None:
        mock_verify.return_value = _make_failing_report()
        result = runner.invoke(app, ["slsa", "verify", "rune", "--tag", "v1"])
        assert result.exit_code == 1

    @patch("rune_audit.cli.slsa_cmd.verify_slsa")
    def test_verify_json(self, mock_verify: MagicMock) -> None:
        mock_verify.return_value = _make_passing_report()
        result = runner.invoke(app, ["slsa", "verify", "rune", "--tag", "v1", "--format", "json"])
        assert result.exit_code == 0
        assert '"passed": true' in result.output


class TestSlsaVerifyAll:
    @patch("rune_audit.cli.slsa_cmd.verify_slsa_all")
    def test_verify_all_pass(self, mock_verify_all: MagicMock) -> None:
        mock_verify_all.return_value = [_make_passing_report(r) for r in ["rune", "rune-operator"]]
        result = runner.invoke(app, ["slsa", "verify-all", "--tag", "v1"])
        assert result.exit_code == 0

    @patch("rune_audit.cli.slsa_cmd.verify_slsa_all")
    def test_verify_all_fail(self, mock_verify_all: MagicMock) -> None:
        mock_verify_all.return_value = [_make_passing_report("rune"), _make_failing_report("rune-operator")]
        result = runner.invoke(app, ["slsa", "verify-all", "--tag", "v1"])
        assert result.exit_code == 1

    @patch("rune_audit.cli.slsa_cmd.verify_slsa_all")
    def test_verify_all_json(self, mock_verify_all: MagicMock) -> None:
        mock_verify_all.return_value = [_make_passing_report("rune")]
        result = runner.invoke(app, ["slsa", "verify-all", "--tag", "v1", "--format", "json"])
        assert result.exit_code == 0


class TestReportCommands:
    def test_report_full(self) -> None:
        result = runner.invoke(app, ["report", "full"])
        assert result.exit_code == 0
        assert "Full Audit Report" in result.output

    def test_report_summary(self) -> None:
        result = runner.invoke(app, ["report", "summary"])
        assert result.exit_code == 0

    def test_report_delta(self) -> None:
        result = runner.invoke(app, ["report", "delta"])
        assert result.exit_code == 0


class TestConfigShow:
    @patch.dict("os.environ", {"RUNE_AUDIT_GITHUB_TOKEN": ""}, clear=False)
    def test_show(self) -> None:
        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0

    @patch.dict("os.environ", {"RUNE_AUDIT_GITHUB_TOKEN": "secret"}, clear=False)
    def test_show_token_masked(self) -> None:
        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0
        assert "secret" not in result.output
        assert "***" in result.output
