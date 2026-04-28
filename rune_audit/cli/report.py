# SPDX-License-Identifier: Apache-2.0
"""CLI commands for report generation."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from rune_audit.config import AuditConfig
from rune_audit.models.evidence import EvidenceBundle
from rune_audit.reporters.report_generator import ReportGenerator

report_app = typer.Typer(no_args_is_help=True, rich_markup_mode="rich")
console = Console()


def _load_evidence(config: AuditConfig) -> EvidenceBundle:
    """Load evidence bundle (stub -- returns empty bundle)."""
    return EvidenceBundle(repos=config.repos)


def _write_output(content: str, output_path: str | None, label: str) -> None:
    """Write report content to file or stdout."""
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        console.print(f"[green]Report written to {output_path}[/green]")
    else:
        console.print(Panel(content, title=label))


@report_app.command("full")
def report_full(
    output_format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown, json."),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path."),
    config_file: str | None = typer.Option(None, "--config", "-c", help="Path to config file."),
) -> None:
    """Generate a complete audit report."""
    cfg = AuditConfig.load(config_file)
    evidence = _load_evidence(cfg)
    content = ReportGenerator(evidence).generate_full(output_format=output_format)
    _write_output(content, output, "Full Audit Report")


@report_app.command("summary")
def report_summary(
    output_format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown, json."),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path."),
    config_file: str | None = typer.Option(None, "--config", "-c", help="Path to config file."),
) -> None:
    """Generate an executive summary."""
    cfg = AuditConfig.load(config_file)
    evidence = _load_evidence(cfg)
    content = ReportGenerator(evidence).generate_summary(output_format=output_format)
    _write_output(content, output, "Audit Summary")


@report_app.command("delta")
def report_delta(
    since: str = typer.Option("", "--since", "-s", help="Compare against a previous report date."),
    output_format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown, json."),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path."),
    config_file: str | None = typer.Option(None, "--config", "-c", help="Path to config file."),
) -> None:
    """Generate a delta report showing changes since last audit."""
    cfg = AuditConfig.load(config_file)
    evidence = _load_evidence(cfg)
    previous = EvidenceBundle(repos=cfg.repos)
    content = ReportGenerator(evidence).generate_delta(previous, output_format=output_format)
    _write_output(content, output, "Delta Report (since " + (since or "last audit") + ")")
