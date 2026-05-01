# SPDX-License-Identifier: Apache-2.0
"""Sigstore signing engine using cosign CLI."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from rune_audit.sigstore.models import SigningResult, VerificationResult

class SigstoreEngine:
    """Wrapper around cosign binary for keyless signing and verification."""

    def __init__(self, cosign_path: str = "cosign") -> None:
        self._cosign_path = cosign_path

    def sign(self, path: Path) -> SigningResult:
        """Sign an artifact using cosign keyless mode."""
        bundle_path_str = str(path) + ".bundle"
        cmd = [
            self._cosign_path,
            "sign-blob",
            str(path),
            "--bundle", bundle_path_str,
            "--yes",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=120,
                env={**os.environ, "COSIGN_EXPERIMENTAL": "1"}
            )
            if result.returncode != 0:
                raise RuntimeError(f"cosign sign-blob failed: {result.stderr}")
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"cosign sign-blob failed: {exc.stderr}") from exc

        # Parse log_index from stderr: "tlog entry created with index: 42"
        log_index = None
        for line in result.stderr.splitlines():
            if "tlog entry created with index:" in line:
                try:
                    log_index = int(line.split(":")[-1].strip())
                except ValueError:  # pragma: no cover
                    pass

        # Parse signature and certificate from stdout
        signature = None
        certificate = None
        lines = result.stdout.strip().splitlines()
        if lines:
            if "-----BEGIN CERTIFICATE-----" in lines:
                cert_idx = lines.index("-----BEGIN CERTIFICATE-----")
                try:
                    end_idx = lines.index("-----END CERTIFICATE-----", cert_idx)
                    certificate = "\n".join(lines[cert_idx : end_idx + 1])
                    signature = "\n".join(lines[end_idx + 1 :]).strip() or None
                except ValueError:  # pragma: no cover
                    certificate = lines[cert_idx]
                    signature = "\n".join(lines[cert_idx + 1 :]).strip() or None
            else:
                signature = lines[0].strip()

        return SigningResult(
            signature=signature,
            certificate=certificate,
            log_index=log_index,
            bundle_path=bundle_path_str
        )

    def sign_blob(self, data: bytes) -> SigningResult:
        """Sign raw data in memory by writing to a temporary file."""
        fd, temp_path = tempfile.mkstemp(suffix=".blob")
        os.write(fd, data)
        os.close(fd)
        
        path = Path(temp_path)
        try:
            result = self.sign(path)
            return result
        finally:
            if path.exists():
                path.unlink()
            bundle_path = Path(str(path) + ".bundle")
            if bundle_path.exists():
                bundle_path.unlink()  # pragma: no cover

    def verify(self, path: Path, bundle_path: Path | None = None) -> VerificationResult:
        """Verify a signature using cosign."""
        cmd = [self._cosign_path, "verify-blob", str(path)]

        if bundle_path is not None:
            cmd.extend(["--bundle", str(bundle_path)])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if result.returncode != 0:
                return VerificationResult(verified=False, errors=[result.stderr])
            
            signer_identity = None
            issuer = None
            log_entry = None
            
            for line in result.stdout.splitlines():
                if line.startswith("Signer: ") or line.startswith("Subject: "):
                    signer_identity = line.split(": ", 1)[-1].strip()
                elif line.startswith("Issuer: "):
                    issuer = line.split(": ", 1)[-1].strip()
                elif line.startswith("{"):
                    try:
                        log_entry = json.loads(line)
                    except json.JSONDecodeError:  # pragma: no cover
                        pass
            
            return VerificationResult(
                verified=True,
                signer_identity=signer_identity,
                issuer=issuer,
                log_entry=log_entry
            )
            
        except subprocess.CalledProcessError as exc:
            return VerificationResult(verified=False, errors=[exc.stderr])
