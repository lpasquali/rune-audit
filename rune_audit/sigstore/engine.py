# SPDX-License-Identifier: Apache-2.0
"""Sigstore signing engine using cosign CLI."""

from __future__ import annotations

import json
import subprocess
from typing import TYPE_CHECKING

from rune_audit.models.sigstore import SigningResult, SigstoreSignature, VerificationResult

if TYPE_CHECKING:
    from pathlib import Path


class SigstoreEngine:
    """Wrapper around cosign binary for keyless signing and verification."""

    def __init__(self, cosign_path: str = "cosign") -> None:
        self.cosign_path = cosign_path

    def sign(self, path: Path) -> SigningResult:
        """Sign an artifact using cosign keyless mode.

        Requires COSIGN_EXPERIMENTAL=1 or modern cosign and valid OIDC environment.
        """
        if not path.is_file():
            return SigningResult(success=False, errors=[f"Artifact not found: {path}"])

        cmd = [
            self.cosign_path,
            "sign-blob",
            str(path),
            "--bundle", str(path.with_suffix(".bundle")),
            "--yes", # Auto-confirm
        ]

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                env={"COSIGN_EXPERIMENTAL": "1"}
            )

            bundle_path = path.with_suffix(".bundle")
            if not bundle_path.is_file():
                return SigningResult(success=False, errors=["Bundle file was not created by cosign"])

            bundle_data = json.loads(bundle_path.read_text(encoding="utf-8"))

            signature_b64 = ""
            cert_pem = ""
            log_index = 0

            if "dsseEnvelope" in bundle_data:
                sig_obj = bundle_data["dsseEnvelope"]["signatures"][0]
                signature_b64 = sig_obj["sig"]
            elif "messageSignature" in bundle_data:
                signature_b64 = bundle_data["messageSignature"]["signature"]

            if "verificationMaterial" in bundle_data:
                mat = bundle_data["verificationMaterial"]
                if "x509CertificateChain" in mat:
                    cert_pem = mat["x509CertificateChain"]["certificates"][0].get("raw", "")
                if "tlogEntries" in mat:
                    log_index = mat["tlogEntries"][0].get("logIndex", 0)

            return SigningResult(
                success=True,
                signature=SigstoreSignature(
                    signature=signature_b64,
                    cert=cert_pem,
                    integrated_time=0,
                    log_index=log_index
                )
            )
        except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError) as exc:
            return SigningResult(success=False, errors=[str(exc)])

    def verify(self, path: Path, bundle_path: Path | None = None) -> VerificationResult:
        """Verify a signature using cosign."""
        if not path.is_file():
            return VerificationResult(verified=False, errors=[f"File not found: {path}"])

        cmd = [self.cosign_path, "verify-blob", str(path)]

        final_bundle = bundle_path or path.with_suffix(".bundle")
        if final_bundle.is_file():
            cmd.extend(["--bundle", str(final_bundle)])
        else:
            return VerificationResult(verified=False, errors=["No bundle found for verification"])

        # For RUNE we usually verify against the known GitHub OIDC issuer
        cmd.extend([
            "--certificate-identity-regexp", ".*",
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"
        ])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return VerificationResult(
                verified=True,
                signer_identity="verified-via-cosign",
                raw_output=result.stderr
            )
        except subprocess.CalledProcessError as exc:
            return VerificationResult(verified=False, errors=[exc.stderr], raw_output=exc.stderr)
