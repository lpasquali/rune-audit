# SPDX-License-Identifier: Apache-2.0
"""CLI commands for Sigstore signing and verification."""

from __future__ import annotations

from pathlib import Path  # noqa: TC003

import typer
from rich.console import Console

from rune_audit.sigstore.engine import SigstoreEngine

sign_app = typer.Typer(no_args_is_help=True, help="Sigstore signing and verification.")
console = Console()


@sign_app.command("sign")
def sign_artifact(
    path: Path = typer.Argument(..., help="Path to artifact to sign."),  # noqa: B008
    cosign_path: str = typer.Option("cosign", help="Path to cosign binary."),  # noqa: B008
) -> None:
    """Sign an artifact using cosign keyless (OIDC) mode."""
    engine = SigstoreEngine(cosign_path=cosign_path)
    try:
        result = engine.sign(path)
        console.print("[green]Signed successfully.[/green]")
        console.print(f"  Signature: {result.signature[:40]}...")
        console.print(f"  Log index: {result.log_index}")
        console.print(f"  Bundle: {result.bundle_path}")
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from None


@sign_app.command("verify")
def verify_artifact(
    path: Path = typer.Argument(..., help="Path to artifact to verify."),  # noqa: B008
    bundle: Path | None = typer.Option(None, "--bundle", help="Path to cosign bundle."),  # noqa: B008
    cosign_path: str = typer.Option("cosign", help="Path to cosign binary."),  # noqa: B008
) -> None:
    """Verify a cosign signature on an artifact."""
    engine = SigstoreEngine(cosign_path=cosign_path)
    result = engine.verify(path, bundle_path=bundle)
    if result.verified:
        console.print("[green]Verification passed.[/green]")
        if result.signer_identity:
            console.print(f"  Signer: {result.signer_identity}")
        if result.issuer:
            console.print(f"  Issuer: {result.issuer}")
    else:
        console.print("[red]Verification failed.[/red]")
        for err in result.errors:
            console.print(f"  Error: {err}")
        raise typer.Exit(code=1)
