# SPDX-License-Identifier: Apache-2.0
"""CLI commands for Rekor transparency log queries."""

from __future__ import annotations

import json

import typer
from rich.console import Console

from rune_audit.rekor.client import RekorClient

rekor_app = typer.Typer(no_args_is_help=True, help="Rekor transparency log operations.")
console = Console()


@rekor_app.command("search")
def search(
    hash_value: str | None = typer.Option(None, "--hash", help="SHA-256 hash to search for."),  # noqa: B008
    email: str | None = typer.Option(None, "--email", help="Signer email to search for."),  # noqa: B008
    base_url: str = typer.Option(  # noqa: B008
        "https://rekor.sigstore.dev", "--url", help="Rekor instance URL."
    ),
) -> None:
    """Search Rekor transparency log by hash or email."""
    if not hash_value and not email:
        console.print("[red]Error:[/red] Provide --hash or --email")
        raise typer.Exit(code=1)

    with RekorClient(base_url=base_url) as client:
        uuids = client.search_by_hash(hash_value) if hash_value else client.search_by_email(email or "")

    if not uuids:
        console.print("No entries found.")
    else:
        console.print(f"Found {len(uuids)} entries:")
        for u in uuids:
            console.print(f"  {u}")


@rekor_app.command("get")
def get_entry(
    uuid: str = typer.Argument(..., help="Entry UUID to retrieve."),  # noqa: B008
    base_url: str = typer.Option(  # noqa: B008
        "https://rekor.sigstore.dev", "--url", help="Rekor instance URL."
    ),
) -> None:
    """Get a specific Rekor log entry."""
    with RekorClient(base_url=base_url) as client:
        try:
            entry = client.get_entry(uuid)
            console.print_json(json.dumps(entry.model_dump(), indent=2))
        except RuntimeError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from None


@rekor_app.command("log-info")
def log_info(
    base_url: str = typer.Option(  # noqa: B008
        "https://rekor.sigstore.dev", "--url", help="Rekor instance URL."
    ),
) -> None:
    """Show Rekor transparency log information."""
    with RekorClient(base_url=base_url) as client:
        try:
            info = client.get_log_info()
            console.print(f"Tree size: {info.tree_size}")
            console.print(f"Root hash: {info.root_hash}")
            console.print(f"Tree ID:   {info.tree_id}")
        except RuntimeError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1) from None
