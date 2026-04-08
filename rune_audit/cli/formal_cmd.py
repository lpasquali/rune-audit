# SPDX-License-Identifier: Apache-2.0
"""CLI commands for TLA+ formal verification."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from rune_audit.formal.checker import TLAChecker

formal_app = typer.Typer(no_args_is_help=True, rich_markup_mode="rich")
console = Console()


@formal_app.command("check")
def formal_check(
    spec: str = typer.Argument(help="Specification name (e.g., AuditChain)"),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to TLC config file."),
    specs_dir: str | None = typer.Option(None, "--specs-dir", help="Directory containing .tla files."),
) -> None:
    """Run TLC model checker on a TLA+ specification."""
    checker = TLAChecker(specs_dir=Path(specs_dir) if specs_dir else None)
    spec_path = checker.specs_dir / f"{spec}.tla"
    if not spec_path.exists():
        console.print(f"[red]Specification not found: {spec_path}[/red]")
        raise typer.Exit(code=1)

    config_path = Path(config) if config else None
    console.print(f"Running TLC on [bold]{spec}[/bold]...")
    result = checker.check(spec_path, config_path=config_path)

    if result.passed:
        console.print(f"[green]PASS[/green] - {result.states_found} states, {result.distinct_states} distinct")
    else:
        console.print(f"[red]FAIL[/red] - {len(result.violations)} violation(s)")
        for v in result.violations:
            console.print(f"  [red]{v}[/red]")
    console.print(f"Duration: {result.duration_seconds:.3f}s")


@formal_app.command("list")
def formal_list(
    specs_dir: str | None = typer.Option(None, "--specs-dir", help="Directory containing .tla files."),
) -> None:
    """List available TLA+ specifications."""
    checker = TLAChecker(specs_dir=Path(specs_dir) if specs_dir else None)
    specs = checker.list_specs()
    if not specs:
        console.print("[yellow]No specifications found.[/yellow]")
        raise typer.Exit(code=0)
    table = Table(title="TLA+ Specifications")
    table.add_column("Name", style="bold")
    table.add_column("Path")
    table.add_column("Description")
    for s in specs:
        table.add_row(s.name, str(s.path), s.description)
    console.print(table)
