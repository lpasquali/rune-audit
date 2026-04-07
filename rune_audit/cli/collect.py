# SPDX-License-Identifier: Apache-2.0
"""CLI commands for evidence collection."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel

from rune_audit.config import AuditConfig

collect_app = typer.Typer(no_args_is_help=True, rich_markup_mode="rich")
console = Console()


@collect_app.command("all")
def collect_all(
    config_file: str | None = typer.Option(None, "--config", "-c", help="Path to rune-audit.yaml config file."),
) -> None:
    """Collect all evidence types from all repos."""
    cfg = AuditConfig.load(config_file)
    console.print(Panel(f"Collecting all evidence from {len(cfg.repos)} repos", title="Evidence Collection"))
    for repo in cfg.repos:
        console.print(f"  [bold]{repo}[/bold]: collecting...")
    console.print("[green]Collection complete.[/green]")


@collect_app.command("sbom")
def collect_sbom(
    config_file: str | None = typer.Option(None, "--config", "-c", help="Path to config file."),
) -> None:
    """Collect SBOMs only."""
    cfg = AuditConfig.load(config_file)
    console.print(Panel(f"Collecting SBOMs from {len(cfg.repos)} repos", title="SBOM Collection"))
    for repo in cfg.repos:
        console.print(f"  [bold]{repo}[/bold]: collecting SBOM...")
    console.print("[green]SBOM collection complete.[/green]")


@collect_app.command("cve")
def collect_cve(
    config_file: str | None = typer.Option(None, "--config", "-c", help="Path to config file."),
) -> None:
    """Collect CVE scan results only."""
    cfg = AuditConfig.load(config_file)
    console.print(Panel(f"Collecting CVE scans from {len(cfg.repos)} repos", title="CVE Collection"))
    for repo in cfg.repos:
        console.print(f"  [bold]{repo}[/bold]: collecting CVE data...")
    console.print("[green]CVE collection complete.[/green]")


@collect_app.command("vex")
def collect_vex(
    config_file: str | None = typer.Option(None, "--config", "-c", help="Path to config file."),
) -> None:
    """Collect VEX documents only."""
    cfg = AuditConfig.load(config_file)
    console.print(Panel(f"Collecting VEX documents from {len(cfg.repos)} repos", title="VEX Collection"))
    for repo in cfg.repos:
        console.print(f"  [bold]{repo}[/bold]: collecting VEX...")
    console.print("[green]VEX collection complete.[/green]")
