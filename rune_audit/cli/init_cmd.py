# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: B008, PLR0913, PLR0915 — Typer CLI patterns match other rune_audit.cli modules
"""``rune-audit init`` — bootstrap compliance-config.yaml (rune-docs#231)."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from rune_audit.sr2.compliance_config import compliance_config_template
from rune_audit.sr2.packs import BUILTIN_PACK_STEMS
from rune_audit.sr2.project_config import default_project_template

console = Console()


def register_init(app: typer.Typer) -> None:
    """Attach ``init`` to the root Typer *app*."""

    @app.command("init")
    def init_command(
        output: Path = typer.Option(
            Path("compliance-config.yaml"),
            "--output",
            "-o",
            help="Path for compliance-config.yaml",
        ),
        project_file: Path = typer.Option(
            Path(".rune-audit-project.yaml"),
            "--project-file",
            help="Optional .rune-audit-project.yaml path",
        ),
        org: str | None = typer.Option(None, "--org", help="GitHub org / owner (non-interactive)"),
        repos: str | None = typer.Option(
            None,
            "--repos",
            help="Comma-separated repository names (non-interactive)",
        ),
        project_name: str | None = typer.Option(None, "--project-name", help="Display name"),
        standard: str = typer.Option("iec-62443-4-1", "--standard", help="Compliance standard label"),
        pack: str = typer.Option(
            "iec-62443-ml4",
            "--pack",
            help=f"Suggested builtin pack stem: one of {', '.join(sorted(BUILTIN_PACK_STEMS))}",
        ),
        force: bool = typer.Option(False, "--force", help="Overwrite existing files"),
        yes: bool = typer.Option(
            False,
            "-y",
            "--yes",
            help="Non-interactive (requires --org and --repos)",
        ),
        write_project_file: bool = typer.Option(
            True,
            "--write-project-file/--no-project-file",
            help="Also write .rune-audit-project.yaml",
        ),
    ) -> None:
        """Generate ``compliance-config.yaml`` (and optional project file) for a non-RUNE codebase."""
        if output.exists() and not force:
            console.print(f"[red]refusing to overwrite {output} (use --force)[/red]")
            raise typer.Exit(1)
        if write_project_file and project_file.exists() and not force:
            console.print(f"[red]refusing to overwrite {project_file} (use --force)[/red]")
            raise typer.Exit(1)

        if yes:
            if not org or not repos:
                console.print("[red]--yes requires --org and --repos[/red]")
                raise typer.Exit(1)
            name = project_name or Path.cwd().name
            repo_list = [r.strip() for r in repos.split(",") if r.strip()]
        else:
            name = project_name or typer.prompt("Project name", default=Path.cwd().name)
            org = org or typer.prompt("GitHub org", default="my-org")
            repos_in = repos or typer.prompt("Repos (comma-separated)", default="core")
            repo_list = [r.strip() for r in repos_in.split(",") if r.strip()]
            standard = typer.prompt("Compliance standard", default=standard)
            pack = typer.prompt("Builtin pack stem", default=pack)

        pack_ref = pack if pack.startswith("builtin://") else f"builtin://{pack}"
        text = compliance_config_template(
            project_name=name,
            github_org=org,
            repo_names=repo_list,
            standard=standard,
            pack=pack_ref,
        )
        output.write_text(text, encoding="utf-8")
        console.print(f"[green]wrote[/green] {output}")
        if write_project_file:
            project_file.write_text(default_project_template(), encoding="utf-8")
            console.print(f"[green]wrote[/green] {project_file}")
        console.print(f"[dim]Suggested next: run `rune-audit sr2 verify --pack {pack}` on a clone.[/dim]")
