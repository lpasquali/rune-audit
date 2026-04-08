# SPDX-License-Identifier: Apache-2.0
"""Sigstore signing engine using cosign CLI subprocess."""

from __future__ import annotations

import contextlib
import json
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from rune_audit.sigstore.models import SigningResult, VerificationResult


class SigstoreEngine:
    """Sign and verify artifacts using cosign (keyless OIDC mode)."""

    def __init__(self, cosign_path: str = "cosign") -> None:
        self._cosign_path = cosign_path

    def sign(self, artifact_path: Path) -> SigningResult:
        """Sign an artifact using cosign keyless (OIDC) mode.

        Args:
            artifact_path: Path to the artifact to sign.

        Returns:
            A SigningResult with signature, certificate, and optional log index.

        Raises:
            RuntimeError: If cosign exits with a non-zero status.
        """
        bundle_path = str(artifact_path) + ".bundle"
        result = subprocess.run(  # noqa: S603
            [
                self._cosign_path,
                "sign-blob",
                "--yes",
                "--bundle",
                bundle_path,
                str(artifact_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"cosign sign-blob failed: {result.stderr.strip()}")

        return self._parse_sign_output(result.stdout, result.stderr, bundle_path)

    def verify(
        self,
        artifact_path: Path,
        bundle_path: Path | None = None,
    ) -> VerificationResult:
        """Verify a cosign signature on an artifact.

        Args:
            artifact_path: Path to the artifact to verify.
            bundle_path: Optional path to the cosign bundle file.

        Returns:
            A VerificationResult indicating whether verification succeeded.
        """
        cmd = [
            self._cosign_path,
            "verify-blob",
            str(artifact_path),
        ]
        if bundle_path is not None:
            cmd.extend(["--bundle", str(bundle_path)])

        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            return VerificationResult(
                verified=False,
                errors=[result.stderr.strip()],
            )

        return self._parse_verify_output(result.stdout, result.stderr)

    def sign_blob(self, data: bytes) -> SigningResult:
        """Sign raw bytes by writing to a temporary file and signing.

        Args:
            data: Raw bytes to sign.

        Returns:
            A SigningResult for the signed data.

        Raises:
            RuntimeError: If cosign exits with a non-zero status.
        """
        with tempfile.NamedTemporaryFile(suffix=".blob", delete=False) as tmp:
            tmp.write(data)
            tmp.flush()
            tmp_path = Path(tmp.name)
        try:
            return self.sign(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)
            bundle = Path(str(tmp_path) + ".bundle")
            bundle.unlink(missing_ok=True)

    def _parse_sign_output(
        self, stdout: str, stderr: str, bundle_path: str
    ) -> SigningResult:
        """Parse cosign sign-blob output into a SigningResult."""
        signature = ""
        certificate = ""
        log_index: int | None = None

        for line in (stdout + "\n" + stderr).splitlines():
            stripped = line.strip()
            if stripped.startswith("MEUCIf") or stripped.startswith("MEUCIQ"):
                signature = stripped
            elif stripped.startswith("-----BEGIN CERTIFICATE-----"):
                certificate = stripped
            elif "tlog entry created with index:" in stripped.lower():
                parts = stripped.split(":")
                with contextlib.suppress(ValueError, IndexError):
                    log_index = int(parts[-1].strip())

        return SigningResult(
            signature=signature,
            certificate=certificate,
            log_index=log_index,
            timestamp=datetime.now(tz=UTC),
            bundle_path=bundle_path,
        )

    def _parse_verify_output(self, stdout: str, stderr: str) -> VerificationResult:
        """Parse cosign verify-blob output into a VerificationResult."""
        signer_identity: str | None = None
        issuer: str | None = None
        log_entry: dict | None = None  # type: ignore[type-arg]

        combined = stdout + "\n" + stderr
        for line in combined.splitlines():
            stripped = line.strip()
            if "signer:" in stripped.lower() or "subject:" in stripped.lower():
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    signer_identity = parts[1].strip()
            elif "issuer:" in stripped.lower():
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    issuer = parts[1].strip()

        # Try to parse JSON log entry from output
        for line in combined.splitlines():
            stripped = line.strip()
            if stripped.startswith("{"):
                with contextlib.suppress(json.JSONDecodeError):
                    log_entry = json.loads(stripped)

        return VerificationResult(
            verified=True,
            signer_identity=signer_identity,
            issuer=issuer,
            log_entry=log_entry,
        )
