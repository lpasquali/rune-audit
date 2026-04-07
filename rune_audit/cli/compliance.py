# SPDX-License-Identifier: Apache-2.0
"""CLI commands for compliance reporting."""

from __future__ import annotations

import json as json_mod

import typer
from rich.console import Console
from rich.table import Table

compliance_app = typer.Typer(no_args_is_help=True, rich_markup_mode="rich")
console = Console()

_EVIDENCE_ITEMS = [
    {"id": "SM-1", "desc": "Development process documentation", "status": "met", "source": "CONTRIBUTING.md"},
    {"id": "SM-2", "desc": "License compliance", "status": "met", "source": "LICENSE (Apache-2.0)"},
    {"id": "SM-7", "desc": "Security response process", "status": "met", "source": "SECURITY.md"},
    {"id": "SM-8", "desc": "Secret detection", "status": "met", "source": "gitleaks in CI"},
    {"id": "SM-9", "desc": "SBOM provenance", "status": "partial", "source": "SLSA L3 attestation"},
    {"id": "DM-4", "desc": "Vulnerability handling", "status": "partial", "source": "VEX register"},
    {"id": "SI-1", "desc": "Security implementation review", "status": "gap", "source": "Pending"},
    {"id": "SI-2", "desc": "Secure coding standards", "status": "met", "source": "ruff + mypy in CI"},
    {"id": "SVV-1", "desc": "Security verification testing", "status": "partial", "source": "97% coverage gate"},
    {"id": "SVV-4", "desc": "Vulnerability scanning", "status": "met", "source": "pip-audit / grype in CI"},
]

_STATUS_STYLES = {
    "met": "[green]MET[/green]",
    "partial": "[yellow]PARTIAL[/yellow]",
    "gap": "[red]GAP[/red]",
    "n/a": "[dim]N/A[/dim]",
}


@compliance_app.command("matrix")
def evidence_matrix(
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json."),
) -> None:
    """Show full IEC 62443 evidence matrix."""
    if output_format == "json":
        console.print_json(json_mod.dumps(_EVIDENCE_ITEMS))
        return

    table = Table(title="IEC 62443 Evidence Matrix")
    table.add_column("Requirement", style="cyan", no_wrap=True)
    table.add_column("Description")
    table.add_column("Status")
    table.add_column("Source")

    for item in _EVIDENCE_ITEMS:
        table.add_row(item["id"], item["desc"], _STATUS_STYLES.get(item["status"], item["status"]), item["source"])

    console.print(table)

    met = sum(1 for i in _EVIDENCE_ITEMS if i["status"] == "met")
    gaps = sum(1 for i in _EVIDENCE_ITEMS if i["status"] == "gap")
    partial = sum(1 for i in _EVIDENCE_ITEMS if i["status"] == "partial")
    console.print(
        f"\n[bold]Summary[/bold]: {met} met, {partial} partial, {gaps} gaps out of {len(_EVIDENCE_ITEMS)} requirements"
    )


@compliance_app.command("gaps")
def show_gaps() -> None:
    """Show unmet IEC 62443 requirements."""
    gap_items = [i for i in _EVIDENCE_ITEMS if i["status"] in ("gap", "partial")]

    if not gap_items:
        console.print("[green]No gaps found --- all requirements met.[/green]")
        return

    table = Table(title="Compliance Gaps")
    table.add_column("Requirement", style="cyan", no_wrap=True)
    table.add_column("Description")
    table.add_column("Status")
    table.add_column("Details")

    for item in gap_items:
        table.add_row(item["id"], item["desc"], _STATUS_STYLES.get(item["status"], item["status"]), item["source"])

    console.print(table)
