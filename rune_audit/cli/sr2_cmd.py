# SPDX-License-Identifier: Apache-2.0
"""CLI: SR-2 quantitative requirement verification."""
# ruff: noqa: B008 # Typer uses runtime defaults for CLI parameters (matches other rune_audit.cli modules)

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from rune_audit.sr2.engine import exit_code_for, run_verification, summarize
from rune_audit.sr2.models import Priority
from rune_audit.sr2.project_config import default_project_template, load_project_file

sr2_app = typer.Typer(no_args_is_help=True, rich_markup_mode="rich")
console = Console()


@sr2_app.command("verify")
def verify_cmd(
    path: Path = typer.Argument(
        Path("."),
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Repository root to verify.",
    ),
    priority: str | None = typer.Option(
        None,
        "--priority",
        "-p",
        help="Only run requirements with this priority (P0, P1, P2).",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Exit with code 2 if any inspector is still not_implemented.",
    ),
    json_out: bool = typer.Option(False, "--json", help="Print machine-readable report."),
) -> None:
    """Run SR-2 inspectors against a repository (stubs until #211 lands)."""
    prio: Priority | None = None
    if priority is not None:
        prio = Priority(priority.upper())
    root = path
    report = run_verification(root=root, priority=prio)
    if json_out:
        console.print_json(data=report.model_dump())
    else:
        counts = summarize(report)
        console.print(f"[bold]SR-2 verify[/bold] root={report.root or str(root.resolve())}")
        console.print(counts)
    code = exit_code_for(report, strict=strict)
    raise typer.Exit(code)


@sr2_app.command("gaps")
def gaps_cmd(
    priority: str | None = typer.Option(None, "--priority", "-p"),
) -> None:
    """List requirements that are not_implemented (stub phase)."""
    prio: Priority | None = Priority(priority.upper()) if priority else None
    report = run_verification(root=Path("."), priority=prio)
    for r in report.results:
        if r.status.value == "not_implemented":
            console.print(f"{r.requirement_id}\t{r.detail}")


@sr2_app.command("dashboard")
def dashboard_cmd(
    format_: str = typer.Option("md", "--format", "-f", help="md | json"),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Emit a minimal compliance summary table (full HTML dashboard: #212)."""
    report = run_verification(root=Path("."), priority=None)
    counts = summarize(report)
    if format_ == "json":
        import json

        text = json.dumps({"summary": counts, "results": [x.model_dump() for x in report.results]}, indent=2)
    else:
        lines = ["# SR-2 dashboard (stub)", "", "| Status | Count |", "| --- | --- |"]
        for k, v in sorted(counts.items()):
            lines.append(f"| {k} | {v} |")
        text = "\n".join(lines) + "\n"
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"wrote {output}")
    else:
        console.print(text)


@sr2_app.command("init")
def init_cmd(
    dest: Path = typer.Option(
        Path(".rune-audit-project.yaml"),
        "--output",
        "-o",
        help="Path for new project file.",
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite existing file."),
) -> None:
    """Write a starter `.rune-audit-project.yaml` (EPIC #231)."""
    if dest.exists() and not force:
        console.print(f"[red]refusing to overwrite {dest} (use --force)[/red]")
        raise typer.Exit(1)
    dest.write_text(default_project_template(), encoding="utf-8")
    console.print(f"wrote {dest}")


@sr2_app.command("config-validate")
def config_validate_cmd(
    project_file: Path = typer.Argument(..., exists=True, dir_okay=False),
) -> None:
    """Validate a `.rune-audit-project.yaml` file."""
    load_project_file(project_file)
    console.print(f"[green]OK[/green] {project_file}")
