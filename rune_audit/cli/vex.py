"""CLI commands for VEX document management."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

vex_app = typer.Typer(no_args_is_help=True, rich_markup_mode="rich")
console = Console()


@vex_app.command("list")
def vex_list(
    vex_dir: str = typer.Option(".vex", "--dir", "-d", help="Path to .vex directory."),
) -> None:
    """List all VEX statements."""
    vex_path = Path(vex_dir)
    if not vex_path.exists():
        console.print("[yellow]No VEX documents found.[/yellow]")
        raise typer.Exit()

    table = Table(title="VEX Statements")
    table.add_column("Document", style="cyan")
    table.add_column("Vulnerability", style="bold")
    table.add_column("Status", style="magenta")
    table.add_column("Justification")

    found = False
    for f in sorted(vex_path.rglob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            for stmt in data.get("statements", []):
                vuln = stmt.get("vulnerability", {})
                vuln_name = vuln.get("name", vuln) if isinstance(vuln, dict) else str(vuln)
                table.add_row(
                    data.get("@id", f.name),
                    str(vuln_name),
                    stmt.get("status", "unknown"),
                    stmt.get("justification", ""),
                )
                found = True
        except (json.JSONDecodeError, KeyError):
            console.print(f"[yellow]Warning: could not parse {f}[/yellow]")

    if not found:
        console.print("[yellow]No VEX documents found.[/yellow]")
        raise typer.Exit()
    console.print(table)


@vex_app.command("validate")
def vex_validate(
    vex_dir: str = typer.Option(".vex", "--dir", "-d", help="Path to .vex directory."),
) -> None:
    """Validate VEX documents against OpenVEX spec."""
    vex_path = Path(vex_dir)
    if not vex_path.exists():
        console.print("[yellow]No .vex directory found.[/yellow]")
        raise typer.Exit(code=1)

    errors: list[str] = []
    checked = 0
    for f in sorted(vex_path.rglob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            required = {"@context", "@id", "author", "timestamp", "version", "statements"}
            missing = required - set(data.keys())
            if missing:
                errors.append(f"{f}: missing required fields: {sorted(missing)}")
            else:
                console.print(f"[green]OK[/green]: {f}")
                checked += 1
        except json.JSONDecodeError as exc:
            errors.append(f"{f}: invalid JSON: {exc}")

    if errors:
        for err in errors:
            console.print(f"[red]ERROR[/red]: {err}")
        raise typer.Exit(code=1)
    console.print(f"[green]Validated {checked} VEX document(s)[/green]")


@vex_app.command("cross-check")
def vex_cross_check(
    vex_dir: str = typer.Option(".vex", "--dir", "-d", help="Path to .vex directory."),
) -> None:
    """Compare VEX statements vs latest CVE scans."""
    vex_path = Path(vex_dir)
    if not vex_path.exists():
        console.print("[yellow]No VEX documents found.[/yellow]")
        raise typer.Exit()

    total = 0
    for f in sorted(vex_path.rglob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            total += len(data.get("statements", []))
        except (json.JSONDecodeError, KeyError):
            pass

    if total == 0:
        console.print("[yellow]No VEX statements found.[/yellow]")
        raise typer.Exit()

    console.print(f"[bold]Cross-checking {total} VEX statements against latest scans...[/bold]")
    console.print("[yellow]Note: Full CVE scan integration pending (issue #13).[/yellow]")
