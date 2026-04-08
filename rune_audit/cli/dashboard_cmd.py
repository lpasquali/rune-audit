# SPDX-License-Identifier: Apache-2.0
"""CLI command for the cross-repo quality gate dashboard."""
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from rune_audit.dashboard.collector import DashboardCollector
from rune_audit.dashboard.renderer import DashboardRenderer

dashboard_app = typer.Typer(no_args_is_help=False, rich_markup_mode="rich")
console = Console()

@dashboard_app.callback(invoke_without_command=True)
def dashboard(
    output_format: str = typer.Option("terminal", "--format", "-f", help="Output format: terminal, markdown, json."),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path."),
) -> None:
    """Show cross-repo quality gate dashboard."""
    collector = DashboardCollector()
    data = collector.collect_all()
    renderer = DashboardRenderer()

    if output_format == "json":
        content = renderer.render_json(data)
    elif output_format == "markdown":
        content = renderer.render_markdown(data)
    else:
        content = renderer.render_terminal(data)

    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        console.print(f"[green]Dashboard written to {output}[/green]")
    else:
        console.print(Panel(content, title="RUNE Dashboard"))
