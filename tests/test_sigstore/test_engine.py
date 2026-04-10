# SPDX-License-Identifier: Apache-2.0
"""Tests for the Sigstore signing engine."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from rune_audit.sigstore.engine import SigstoreEngine
from rune_audit.sigstore.models import SigningResult, VerificationResult


class TestSigningResult:
    """Tests for SigningResult model."""

    def test_create_minimal(self) -> None:
        result = SigningResult(
            signature="MEUCIf...",
            certificate="-----BEGIN CERTIFICATE-----",
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        )
        assert result.signature == "MEUCIf..."
        assert result.log_index is None
        assert result.bundle_path is None

    def test_create_full(self) -> None:
        result = SigningResult(
            signature="MEUCIf...",
            certificate="-----BEGIN CERTIFICATE-----",
            log_index=12345,
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            bundle_path="/tmp/test.bundle",
        )
        assert result.log_index == 12345
        assert result.bundle_path == "/tmp/test.bundle"

    def test_serialization(self) -> None:
        result = SigningResult(
            signature="sig",
            certificate="cert",
            log_index=1,
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            bundle_path="/tmp/b",
        )
        data = result.model_dump()
        assert data["signature"] == "sig"
        assert data["log_index"] == 1
        restored = SigningResult.model_validate(data)
        assert restored == result


class TestVerificationResult:
    """Tests for VerificationResult model."""

    def test_verified_true(self) -> None:
        result = VerificationResult(verified=True, signer_identity="user@example.com")
        assert result.verified is True
        assert result.errors == []

    def test_verified_false_with_errors(self) -> None:
        result = VerificationResult(verified=False, errors=["bad sig", "expired cert"])
        assert result.verified is False
        assert len(result.errors) == 2

    def test_with_log_entry(self) -> None:
        entry = {"uuid": "abc", "logIndex": 100}
        result = VerificationResult(verified=True, log_entry=entry)
        assert result.log_entry is not None
        assert result.log_entry["uuid"] == "abc"

    def test_serialization(self) -> None:
        result = VerificationResult(
            verified=True,
            signer_identity="user@example.com",
            issuer="https://accounts.google.com",
            log_entry={"uuid": "abc"},
        )
        data = result.model_dump()
        assert data["verified"] is True
        restored = VerificationResult.model_validate(data)
        assert restored == result


class TestSigstoreEngineSign:
    """Tests for SigstoreEngine.sign()."""

    def test_sign_success(self, tmp_path: Path) -> None:
        artifact = tmp_path / "artifact.txt"
        artifact.write_text("hello")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "MEUCIf_test_signature_base64\n"
        mock_result.stderr = "tlog entry created with index: 42\n"

        with patch("rune_audit.sigstore.engine.subprocess.run", return_value=mock_result) as mock_run:
            engine = SigstoreEngine(cosign_path="/usr/bin/cosign")
            result = engine.sign(artifact)

        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[0][0][0] == "/usr/bin/cosign"
        assert "sign-blob" in call_args[0][0]
        assert result.signature == "MEUCIf_test_signature_base64"
        assert result.log_index == 42
        assert result.bundle_path == str(artifact) + ".bundle"

    def test_sign_failure(self, tmp_path: Path) -> None:
        artifact = tmp_path / "artifact.txt"
        artifact.write_text("hello")

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: no identity token provided"

        with patch("rune_audit.sigstore.engine.subprocess.run", return_value=mock_result):
            engine = SigstoreEngine()
            with pytest.raises(RuntimeError, match="cosign sign-blob failed"):
                engine.sign(artifact)

    def test_sign_with_certificate_in_output(self, tmp_path: Path) -> None:
        artifact = tmp_path / "artifact.txt"
        artifact.write_text("hello")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "-----BEGIN CERTIFICATE-----\nMEUCIQ_signature\n"
        mock_result.stderr = ""

        with patch("rune_audit.sigstore.engine.subprocess.run", return_value=mock_result):
            engine = SigstoreEngine()
            result = engine.sign(artifact)

        assert result.certificate == "-----BEGIN CERTIFICATE-----"
        assert result.signature == "MEUCIQ_signature"
        assert result.log_index is None

    def test_sign_timeout_passed(self, tmp_path: Path) -> None:
        artifact = tmp_path / "artifact.txt"
        artifact.write_text("hello")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("rune_audit.sigstore.engine.subprocess.run", return_value=mock_result) as mock_run:
            engine = SigstoreEngine()
            engine.sign(artifact)

        assert mock_run.call_args[1]["timeout"] == 120

    def test_sign_log_index_parse_error(self, tmp_path: Path) -> None:
        """Log index line with non-numeric value is gracefully ignored."""
        artifact = tmp_path / "artifact.txt"
        artifact.write_text("hello")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = "tlog entry created with index: not-a-number\n"

        with patch("rune_audit.sigstore.engine.subprocess.run", return_value=mock_result):
            engine = SigstoreEngine()
            result = engine.sign(artifact)

        assert result.log_index is None


class TestSigstoreEngineVerify:
    """Tests for SigstoreEngine.verify()."""

    def test_verify_success(self, tmp_path: Path) -> None:
        artifact = tmp_path / "artifact.txt"
        artifact.write_text("hello")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'Signer: user@example.com\nIssuer: https://accounts.google.com\n{"uuid":"abc"}\n'
        mock_result.stderr = ""

        with patch("rune_audit.sigstore.engine.subprocess.run", return_value=mock_result):
            engine = SigstoreEngine()
            result = engine.verify(artifact)

        assert result.verified is True
        assert result.signer_identity == "user@example.com"
        assert result.issuer == "https://accounts.google.com"
        assert result.log_entry == {"uuid": "abc"}

    def test_verify_failure(self, tmp_path: Path) -> None:
        artifact = tmp_path / "artifact.txt"
        artifact.write_text("hello")

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: invalid signature"

        with patch("rune_audit.sigstore.engine.subprocess.run", return_value=mock_result):
            engine = SigstoreEngine()
            result = engine.verify(artifact)

        assert result.verified is False
        assert "invalid signature" in result.errors[0]

    def test_verify_with_bundle(self, tmp_path: Path) -> None:
        artifact = tmp_path / "artifact.txt"
        artifact.write_text("hello")
        bundle = tmp_path / "artifact.bundle"
        bundle.write_text("{}")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Verified OK\n"
        mock_result.stderr = ""

        with patch("rune_audit.sigstore.engine.subprocess.run", return_value=mock_result) as mock_run:
            engine = SigstoreEngine()
            result = engine.verify(artifact, bundle_path=bundle)

        assert result.verified is True
        cmd = mock_run.call_args[0][0]
        assert "--bundle" in cmd
        assert str(bundle) in cmd

    def test_verify_without_bundle(self, tmp_path: Path) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("rune_audit.sigstore.engine.subprocess.run", return_value=mock_result) as mock_run:
            engine = SigstoreEngine()
            engine.verify(Path("/fake/artifact"))

        cmd = mock_run.call_args[0][0]
        assert "--bundle" not in cmd

    def test_verify_subject_identity(self, tmp_path: Path) -> None:
        """Parse 'Subject:' line as signer identity."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Subject: deploy@company.com\n"
        mock_result.stderr = ""

        with patch("rune_audit.sigstore.engine.subprocess.run", return_value=mock_result):
            engine = SigstoreEngine()
            result = engine.verify(Path("/fake"))

        assert result.signer_identity == "deploy@company.com"

    def test_verify_invalid_json_in_output(self, tmp_path: Path) -> None:
        """Invalid JSON lines are gracefully skipped."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "{not valid json}\n"
        mock_result.stderr = ""

        with patch("rune_audit.sigstore.engine.subprocess.run", return_value=mock_result):
            engine = SigstoreEngine()
            result = engine.verify(Path("/fake"))

        assert result.verified is True
        assert result.log_entry is None


class TestSigstoreEngineSignBlob:
    """Tests for SigstoreEngine.sign_blob()."""

    def test_sign_blob_success(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "MEUCIf_blob_sig\n"
        mock_result.stderr = "tlog entry created with index: 99\n"

        with patch("rune_audit.sigstore.engine.subprocess.run", return_value=mock_result):
            engine = SigstoreEngine()
            result = engine.sign_blob(b"raw data here")

        assert result.signature == "MEUCIf_blob_sig"
        assert result.log_index == 99

    def test_sign_blob_failure(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: failed to sign"

        with patch("rune_audit.sigstore.engine.subprocess.run", return_value=mock_result):
            engine = SigstoreEngine()
            with pytest.raises(RuntimeError, match="cosign sign-blob failed"):
                engine.sign_blob(b"data")

    def test_sign_blob_cleans_up_temp_files(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        temp_paths: list[str] = []

        def capture_path(*args: object, **kwargs: object) -> MagicMock:
            cmd = args[0]
            if isinstance(cmd, list):
                for item in cmd:
                    if isinstance(item, str) and ".blob" in item:
                        temp_paths.append(item)
            return mock_result

        with patch("rune_audit.sigstore.engine.subprocess.run", side_effect=capture_path):
            engine = SigstoreEngine()
            engine.sign_blob(b"temp data")

        # Temp file should have been cleaned up
        assert len(temp_paths) >= 1
        for p in temp_paths:
            assert not Path(p).exists()

    def test_sign_blob_cleans_up_on_error(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: fail"

        with patch("rune_audit.sigstore.engine.subprocess.run", return_value=mock_result):
            engine = SigstoreEngine()
            with pytest.raises(RuntimeError):
                engine.sign_blob(b"data")


class TestSigstoreEngineConstructor:
    """Tests for SigstoreEngine constructor."""

    def test_default_cosign_path(self) -> None:
        engine = SigstoreEngine()
        assert engine._cosign_path == "cosign"

    def test_custom_cosign_path(self) -> None:
        engine = SigstoreEngine(cosign_path="/opt/bin/cosign")
        assert engine._cosign_path == "/opt/bin/cosign"
