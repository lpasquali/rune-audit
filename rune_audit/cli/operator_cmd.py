# SPDX-License-Identifier: Apache-2.0
"""CLI commands for rune-operator audit trail."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from rune_audit.collectors.operator import OperatorCollector

operator_app = typer.Typer(no_args_is_help=True, rich_markup_mode="rich")
console = Console()


@operator_app.command("runs")
def operator_runs(
    namespace: str | None = typer.Option(None, "-n", "--namespace", help="Kubernetes namespace."),
) -> None:
    """List RuneBenchmark run records from the operator."""
    collector = OperatorCollector()
    records = collector.collect_run_records(namespace=namespace)

    if not records:
        console.print("[yellow]No RuneBenchmark records found.[/yellow]")
        raise typer.Exit(code=0)

    table = Table(title="RuneBenchmark Run Records")
    table.add_column("Name", style="bold")
    table.add_column("Namespace")
    table.add_column("Status")
    table.add_column("Agent")
    table.add_column("Model")
    table.add_column("Created")

    for r in records:
        table.add_row(
            r.name,
            r.namespace,
            r.status,
            r.agent,
            r.model,
            r.created_at.isoformat() if r.created_at else "",
        )
    console.print(table)


@operator_app.command("trail")
def operator_trail(
    run_name: str = typer.Argument(help="RuneBenchmark resource name."),
    namespace: str = typer.Option("default", "-n", "--namespace", help="Kubernetes namespace."),
) -> None:
    """Show audit trail for a specific RuneBenchmark run."""
    collector = OperatorCollector()
    trail = collector.collect_audit_trail(run_name, namespace=namespace)

    if not trail.events and not trail.records:
        console.print(f"[yellow]No audit trail found for {run_name}.[/yellow]")
        raise typer.Exit(code=0)

    if trail.records:
        record = trail.records[0]
        console.print(f"[bold]Run:[/bold] {record.name}")
        console.print(f"[bold]Status:[/bold] {record.status}")
        console.print(f"[bold]Agent:[/bold] {record.agent}")
        console.print(f"[bold]Model:[/bold] {record.model}")
        console.print(f"[bold]Backend:[/bold] {record.backend_type}")
        console.print()

    if trail.events:
        table = Table(title="Audit Events")
        table.add_column("Timestamp")
        table.add_column("Type", style="bold")
        table.add_column("Message")

        for event in trail.events:
            table.add_row(event.timestamp.isoformat(), event.event_type, event.message)
        console.print(table)
