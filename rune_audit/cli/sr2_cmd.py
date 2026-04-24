# SPDX-License-Identifier: Apache-2.0
"""CLI: SR-2 quantitative requirement verification."""
# ruff: noqa: B008 # Typer uses runtime defaults for CLI parameters (matches other rune_audit.cli modules)

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from rune_audit.sr2.compliance_config import resolve_project_repo_paths, try_load_compliance_config
from rune_audit.sr2.dashboard_matrix import (
    build_matrix,
    collect_verify_reports,
    combined_summary,
    load_previous_dashboard,
    render_html,
    render_json_document,
    render_markdown,
    trend_delta,
)
from rune_audit.sr2.engine import exit_code_for, run_pack_verification, run_verification, summarize
from rune_audit.sr2.models import Priority
from rune_audit.sr2.project_config import load_project_file

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
    pack: str | None = typer.Option(
        None,
        "--pack",
        "-k",
        help="Run a builtin YAML pack (e.g. slsa-l3, owasp-asvs) instead of full SR-Q catalog.",
    ),
) -> None:
    """Run SR-2 inspectors against a repository (stubs until #211 lands)."""
    prio: Priority | None = None
    if priority is not None:
        prio = Priority(priority.upper())
    root = path
    report = run_pack_verification(root=root, pack_stem=pack) if pack else run_verification(root=root, priority=prio)
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
    format_: str = typer.Option("md", "--format", "-f", help="md | json | html"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    config: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        help="compliance-config.yaml (default: ./compliance-config.yaml if present else RUNE defaults)",
    ),
    base_path: Path = typer.Option(
        Path(".."),
        "--base-path",
        help="Parent directory containing sibling repo clones (names from config).",
    ),
    previous: Path | None = typer.Option(
        None,
        "--previous",
        help="Prior dashboard JSON for trend delta (same format as --format json output).",
    ),
    single_repo: bool = typer.Option(
        False,
        "--single-repo",
        help="Matrix for current directory only (one column: cwd folder name).",
    ),
) -> None:
    """Multi-repo SR-2 matrix dashboard (rune-docs#212)."""
    fmt = format_.lower().strip()
    if fmt not in ("md", "json", "html"):
        console.print("[red]--format must be md, json, or html[/red]")
        raise typer.Exit(2)

    if single_repo:
        root = Path(".").resolve()
        reports, skipped = collect_verify_reports([(root.name, root)])
    else:
        cfg = try_load_compliance_config(config)
        pairs = resolve_project_repo_paths(cfg, base_path)
        reports, skipped = collect_verify_reports(pairs)

    summary = combined_summary(reports)
    matrix = build_matrix(reports, skipped_repos=skipped)
    prev_doc = load_previous_dashboard(previous) if previous else None
    trend = trend_delta(summary, prev_doc)

    if fmt == "json":
        doc = render_json_document(matrix, summary, trend)
        text = json.dumps(doc, indent=2)
    elif fmt == "html":
        text = render_html(matrix, summary, trend)
    else:
        text = render_markdown(matrix, summary)

    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"wrote {output}")
    else:
        console.print(text)


@sr2_app.command("config-validate")
def config_validate_cmd(
    project_file: Path = typer.Argument(..., exists=True, dir_okay=False),
) -> None:
    """Validate a `.rune-audit-project.yaml` file."""
    load_project_file(project_file)
    console.print(f"[green]OK[/green] {project_file}")
