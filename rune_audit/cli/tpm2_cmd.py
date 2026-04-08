# SPDX-License-Identifier: Apache-2.0
"""CLI commands for TPM2 attestation collection."""

from __future__ import annotations

import json

import typer
from rich.console import Console

from rune_audit.collectors.tpm2 import TPM2Collector

tpm2_app = typer.Typer(no_args_is_help=True, help="TPM2 attestation collection.")
console = Console()


@tpm2_app.command("pcrs")
def read_pcrs(
    pcrs: str = typer.Option("0,1,2,3,7", help="Comma-separated PCR indices."),  # noqa: B008
) -> None:
    """Read TPM2 PCR values."""
    selection = [int(x.strip()) for x in pcrs.split(",")]
    collector = TPM2Collector()
    try:
        bank = collector.collect_pcrs(pcr_selection=selection)
        for idx, val in sorted(bank.values.items()):
            console.print(f"  PCR[{idx:2d}]: {val}")
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from None


@tpm2_app.command("quote")
def collect_quote(
    pcrs: str = typer.Option("0,1,2,3,7", help="Comma-separated PCR indices."),  # noqa: B008
    nonce: str | None = typer.Option(None, help="Anti-replay nonce."),  # noqa: B008
) -> None:
    """Collect a TPM2 attestation quote."""
    selection = [int(x.strip()) for x in pcrs.split(",")]
    collector = TPM2Collector()
    try:
        quote = collector.collect_quote(pcr_selection=selection, nonce=nonce)
        console.print_json(json.dumps(quote.model_dump(), indent=2))
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from None


@tpm2_app.command("eventlog")
def dump_event_log() -> None:
    """Dump the TPM2 event log."""
    collector = TPM2Collector()
    try:
        log = collector.collect_event_log()
        for entry in log.entries:
            console.print(f"  PCR[{entry.pcr_index:2d}] {entry.event_type}: {entry.digest[:16]}...")
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from None


@tpm2_app.command("collect")
def full_collect() -> None:
    """Run full TPM2 attestation collection pipeline."""
    collector = TPM2Collector()
    result = collector.collect()
    if result.passed:
        console.print("[green]TPM2 attestation collected successfully.[/green]")
    else:
        console.print("[red]TPM2 attestation collection had errors:[/red]")
        for err in result.errors:
            console.print(f"  {err}")
    console.print_json(json.dumps(result.model_dump(mode="json"), indent=2))
