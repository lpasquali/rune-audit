"""CLI commands for report generation."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel

from rune_audit.config import AuditConfig

report_app = typer.Typer(no_args_is_help=True, rich_markup_mode="rich")
console = Console()


@report_app.command("full")
def report_full(
    output_format: str = typer.Option("md", "--format", "-f", help="Output format: md, json, html."),
    output_dir: str | None = typer.Option(None, "--output", "-o", help="Output directory."),
    config_file: str | None = typer.Option(None, "--config", "-c", help="Path to config file."),
) -> None:
    """Generate a complete audit report."""
    cfg = AuditConfig.load(config_file)
    if output_dir:
        cfg.output_dir = output_dir
    cfg.output_format = output_format
    console.print(Panel(
        f"Generating full report ({output_format}) to {cfg.output_dir}",
        title="Full Audit Report",
    ))
    console.print("[yellow]Note: Full report generation pending (issue #22).[/yellow]")


@report_app.command("summary")
def report_summary(
    output_format: str = typer.Option("md", "--format", "-f", help="Output format: md, json, html."),
    config_file: str | None = typer.Option(None, "--config", "-c", help="Path to config file."),
) -> None:
    """Generate an executive summary."""
    cfg = AuditConfig.load(config_file)
    cfg.output_format = output_format
    console.print(Panel("Executive Summary", title="Audit Summary"))
    console.print("[yellow]Note: Summary generation pending (issue #22).[/yellow]")


@report_app.command("delta")
def report_delta(
    since: str = typer.Option("", "--since", "-s", help="Compare against a previous report date."),
    output_format: str = typer.Option("md", "--format", "-f", help="Output format: md, json, html."),
    config_file: str | None = typer.Option(None, "--config", "-c", help="Path to config file."),
) -> None:
    """Generate a delta report showing changes since last audit."""
    cfg = AuditConfig.load(config_file)
    cfg.output_format = output_format
    console.print(Panel(
        f"Delta report since: {since or 'last audit'}",
        title="Delta Report",
    ))
    console.print("[yellow]Note: Delta report generation pending (issue #22).[/yellow]")
