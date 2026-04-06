"""CLI commands for configuration display."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from rune_audit.config import AuditConfig

config_app = typer.Typer(no_args_is_help=True, rich_markup_mode="rich")
console = Console()


@config_app.command("show")
def config_show(
    config_file: str | None = typer.Option(None, "--config", "-c", help="Path to config file."),
) -> None:
    """Show current configuration."""
    cfg = AuditConfig.load(config_file)

    table = Table(title="rune-audit Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")

    token_display = "***" if cfg.github_token else "[red]not set[/red]"
    table.add_row("GitHub Token", token_display)
    table.add_row("Repos", ", ".join(cfg.repos))
    table.add_row("Output Directory", cfg.output_dir)
    table.add_row("Output Format", cfg.output_format)

    console.print(table)
