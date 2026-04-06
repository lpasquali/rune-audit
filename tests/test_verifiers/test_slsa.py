"""Tests for the SLSA Level 3 provenance verifier."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from rune_audit.config import AuditConfig
from rune_audit.verifiers.slsa import (
    AttestationBundle,
    SLSACheckResult,
    SLSARequirement,
    SLSAVerificationReport,
    VerificationStatus,
    _check_build_isolated,
    _check_builder_trusted,
    _check_provenance_exists,
    _check_provenance_signed,
    _check_source_version_controlled,
    _extract_predicate,
    _get_github_token,
    collect_attestations,
    verify_slsa,
    verify_slsa_all,
)


class TestAttestationBundle:
    def test_defaults(self) -> None:
        assert AttestationBundle(repo="r", tag="v1").payload == {}
    def test_none(self) -> None:
        assert AttestationBundle(repo="r", tag="v1", payload=None).payload == {}

class TestGetGithubToken:
    @patch.dict("os.environ", {"RUNE_AUDIT_GITHUB_TOKEN": "tok"})
    def test_env(self) -> None:
        assert _get_github_token() == "tok"
    @patch.dict("os.environ", {"RUNE_AUDIT_GITHUB_TOKEN": ""})
    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_none(self, m: MagicMock) -> None:
        assert _get_github_token() == ""

class TestCollect:
    @patch("rune_audit.verifiers.slsa._get_github_token", return_value="")
    def test_no_tok(self, m: MagicMock) -> None:
        assert not collect_attestations("r", "v1").found
    @patch("rune_audit.verifiers.slsa._get_github_token", return_value="t")
    @patch("subprocess.run")
    def test_ok(self, mr: MagicMock, mt: MagicMock) -> None:
        mr.return_value = MagicMock(returncode=0, stdout='{"p": {}}', stderr="")
        assert collect_attestations("r", "v1").found
    @patch("rune_audit.verifiers.slsa._get_github_token", return_value="t")
    @patch("subprocess.run")
    def test_fail(self, mr: MagicMock, mt: MagicMock) -> None:
        mr.return_value = MagicMock(returncode=1, stdout="", stderr="e")
        assert not collect_attestations("r", "v1").found
    @patch("rune_audit.verifiers.slsa._get_github_token", return_value="t")
    @patch("subprocess.run")
    def test_empty(self, mr: MagicMock, mt: MagicMock) -> None:
        mr.return_value = MagicMock(returncode=0, stdout="", stderr="")
        assert not collect_attestations("r", "v1").found
    @patch("rune_audit.verifiers.slsa._get_github_token", return_value="t")
    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_no_gh(self, mr: MagicMock, mt: MagicMock) -> None:
        assert not collect_attestations("r", "v1").found

class TestChecks:
    def test_exists_pass(self, passing_bundle: AttestationBundle) -> None:
        assert _check_provenance_exists(passing_bundle).status == VerificationStatus.PASS
    def test_exists_fail(self, missing_bundle: AttestationBundle) -> None:
        assert _check_provenance_exists(missing_bundle).status == VerificationStatus.FAIL
    def test_signed_pass(self, passing_bundle: AttestationBundle) -> None:
        assert _check_provenance_signed(passing_bundle).status == VerificationStatus.PASS
    def test_signed_skip(self, missing_bundle: AttestationBundle) -> None:
        assert _check_provenance_signed(missing_bundle).status == VerificationStatus.SKIP
    def test_builder_pass(self, passing_bundle: AttestationBundle) -> None:
        assert _check_builder_trusted(passing_bundle).status == VerificationStatus.PASS
    def test_builder_type(self) -> None:
        b = AttestationBundle(repo="t", tag="v", found=True,
            payload={"predicate": {"buildType": "https://actions.github.io/buildtypes/workflow/v1"}})
        assert _check_builder_trusted(b).status == VerificationStatus.PASS
    def test_builder_fail(self) -> None:
        b = AttestationBundle(repo="t", tag="v", found=True,
            payload={"predicate": {"builder": {"id": "evil"}, "buildType": "c"}})
        assert _check_builder_trusted(b).status == VerificationStatus.FAIL
    def test_builder_skip(self, missing_bundle: AttestationBundle) -> None:
        assert _check_builder_trusted(missing_bundle).status == VerificationStatus.SKIP
    def test_builder_slsa(self, gh_verify_bundle: AttestationBundle) -> None:
        assert _check_builder_trusted(gh_verify_bundle).status == VerificationStatus.PASS
    def test_src_v02(self, passing_bundle: AttestationBundle) -> None:
        assert _check_source_version_controlled(passing_bundle).status == VerificationStatus.PASS
    def test_src_v10(self, slsa_v1_bundle: AttestationBundle) -> None:
        assert _check_source_version_controlled(slsa_v1_bundle).status == VerificationStatus.PASS
    def test_src_gh(self, gh_verify_bundle: AttestationBundle) -> None:
        assert _check_source_version_controlled(gh_verify_bundle).status == VerificationStatus.PASS
    def test_src_fail(self) -> None:
        b = AttestationBundle(repo="t", tag="v", found=True, payload={"predicate": {"buildType": "c"}})
        assert _check_source_version_controlled(b).status == VerificationStatus.FAIL
    def test_src_skip(self, missing_bundle: AttestationBundle) -> None:
        assert _check_source_version_controlled(missing_bundle).status == VerificationStatus.SKIP
    def test_src_sha256(self) -> None:
        b = AttestationBundle(repo="t", tag="v", found=True,
            payload={"predicate": {"materials": [{"digest": {"sha256": "aa"}}]}})
        assert _check_source_version_controlled(b).status == VerificationStatus.PASS
    def test_iso_pass(self, passing_bundle: AttestationBundle) -> None:
        assert _check_build_isolated(passing_bundle).status == VerificationStatus.PASS
    def test_iso_type(self) -> None:
        b = AttestationBundle(repo="t", tag="v", found=True,
            payload={"predicate": {"buildType": "https://actions.github.io/buildtypes/workflow/v1"}})
        assert _check_build_isolated(b).status == VerificationStatus.PASS
    def test_iso_run(self, slsa_v1_bundle: AttestationBundle) -> None:
        assert _check_build_isolated(slsa_v1_bundle).status == VerificationStatus.PASS
    def test_iso_fail(self) -> None:
        b = AttestationBundle(repo="t", tag="v", found=True,
            payload={"predicate": {"buildType": "c", "metadata": {}}})
        assert _check_build_isolated(b).status == VerificationStatus.FAIL
    def test_iso_skip(self, missing_bundle: AttestationBundle) -> None:
        assert _check_build_isolated(missing_bundle).status == VerificationStatus.SKIP

class TestExtract:
    def test_direct(self) -> None:
        assert _extract_predicate({"predicate": {"k": "v"}}) == {"k": "v"}
    def test_nested(self) -> None:
        assert _extract_predicate([{"verificationResult": {"statement": {"predicate": {"k": "v"}}}}]) == {"k": "v"}
    def test_empty(self) -> None:
        assert _extract_predicate({}) == {}
    def test_list(self) -> None:
        assert _extract_predicate([]) == {}
    def test_str(self) -> None:
        assert _extract_predicate({"predicate": "s"}) == {}

class TestReport:
    def test_empty(self) -> None:
        assert SLSAVerificationReport(repo="r", tag="v").passed
    def test_gap(self) -> None:
        r = SLSAVerificationReport(repo="r", tag="v")
        r.checks.append(SLSACheckResult(
            requirement=SLSARequirement.BUILD_PROVENANCE_EXISTS,
            status=VerificationStatus.FAIL, message="m"))
        assert not r.passed and len(r.gaps) == 1

class TestVerify:
    def test_pass(self, passing_bundle: AttestationBundle) -> None:
        assert verify_slsa("r", "v", bundle=passing_bundle).passed
    def test_fail(self, missing_bundle: AttestationBundle) -> None:
        assert not verify_slsa("r", "v", bundle=missing_bundle).passed
    def test_v1(self, slsa_v1_bundle: AttestationBundle) -> None:
        assert verify_slsa("r", "v", bundle=slsa_v1_bundle).passed
    def test_gh(self, gh_verify_bundle: AttestationBundle) -> None:
        assert verify_slsa("r", "v", bundle=gh_verify_bundle).passed
    def test_auto(self, passing_bundle: AttestationBundle) -> None:
        with patch("rune_audit.verifiers.slsa.collect_attestations", return_value=passing_bundle):
            assert verify_slsa("r", "v").passed

class TestVerifyAll:
    def test_repos(self, passing_bundle: AttestationBundle) -> None:
        with patch("rune_audit.verifiers.slsa.collect_attestations", return_value=passing_bundle):
            assert len(verify_slsa_all("v", repos=["a", "b"])) == 2
    def test_config(self, passing_bundle: AttestationBundle) -> None:
        with patch("rune_audit.verifiers.slsa.collect_attestations", return_value=passing_bundle):
            assert len(verify_slsa_all("v", config=AuditConfig(repos=["a", "b", "c"]))) == 3
    def test_defaults(self, passing_bundle: AttestationBundle) -> None:
        with patch("rune_audit.verifiers.slsa.collect_attestations", return_value=passing_bundle):
            assert len(verify_slsa_all("v")) == 6
