"""CLI commands for SLSA verification."""

from __future__ import annotations

import json as json_mod

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rune_audit.config import AuditConfig
from rune_audit.verifiers.slsa import (
    VerificationStatus,
    verify_slsa,
    verify_slsa_all,
)

slsa_app = typer.Typer(no_args_is_help=True, rich_markup_mode="rich")
console = Console()

_STATUS_ICONS = {
    VerificationStatus.PASS: "[green]PASS[/green]",
    VerificationStatus.FAIL: "[red]FAIL[/red]",
    VerificationStatus.SKIP: "[yellow]SKIP[/yellow]",
    VerificationStatus.ERROR: "[red]ERROR[/red]",
}


@slsa_app.command("verify")
def slsa_verify(
    repo: str = typer.Argument(help="Repository name (e.g. rune)."),
    tag: str = typer.Option(..., "--tag", "-t", help="Release tag (e.g. v0.0.0a2)."),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json."),
) -> None:
    """Verify SLSA Level 3 provenance for a single release."""
    console.print(Panel(f"Verifying SLSA L3 for [bold]{repo}[/bold] @ {tag}", title="SLSA Verification"))

    report = verify_slsa(repo, tag)

    if output_format == "json":
        data = {
            "repo": report.repo, "tag": report.tag, "passed": report.passed,
            "attestation_found": report.attestation_found,
            "checks": [
                {"requirement": c.requirement.value, "status": c.status.value, "message": c.message}
                for c in report.checks
            ],
        }
        console.print_json(json_mod.dumps(data))
        return

    table = Table(title=f"SLSA L3 Verification: {report.repo} @ {report.tag}")
    table.add_column("Requirement", style="cyan")
    table.add_column("Status")
    table.add_column("Details")
    for check in report.checks:
        table.add_row(
            check.requirement.value.replace("_", " ").title(),
            _STATUS_ICONS.get(check.status, check.status.value),
            check.message,
        )
    console.print(table)

    if report.passed:
        console.print("\n[green bold]All SLSA L3 requirements satisfied.[/green bold]")
    else:
        console.print(f"\n[red bold]{len(report.gaps)} requirement(s) not met.[/red bold]")
        raise typer.Exit(code=1)


@slsa_app.command("verify-all")
def slsa_verify_all(
    tag: str = typer.Option(..., "--tag", "-t", help="Release tag to verify across all repos."),
    config_file: str | None = typer.Option(None, "--config", "-c", help="Path to config file."),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json."),
) -> None:
    """Verify SLSA Level 3 provenance across all ecosystem repos."""
    cfg = AuditConfig.load(config_file)
    console.print(Panel(
        f"Verifying SLSA L3 across {len(cfg.repos)} repos @ {tag}",
        title="Ecosystem SLSA Verification",
    ))

    reports = verify_slsa_all(tag, config=cfg)

    if output_format == "json":
        data = [
            {
                "repo": r.repo, "tag": r.tag, "passed": r.passed,
                "checks_passed": sum(1 for c in r.checks if c.status == VerificationStatus.PASS),
                "checks_total": len(r.checks),
            }
            for r in reports
        ]
        console.print_json(json_mod.dumps(data))
        return

    table = Table(title=f"Ecosystem SLSA L3 Verification @ {tag}")
    table.add_column("Repository", style="bold")
    table.add_column("Attestation")
    table.add_column("Passed")
    table.add_column("Checks")

    all_passed = True
    for report in reports:
        passed_count = sum(1 for c in report.checks if c.status == VerificationStatus.PASS)
        att = "[green]Found[/green]" if report.attestation_found else "[red]Missing[/red]"
        ps = "[green]YES[/green]" if report.passed else "[red]NO[/red]"
        if not report.passed:
            all_passed = False
        table.add_row(report.repo, att, ps, f"{passed_count}/{len(report.checks)}")

    console.print(table)

    if all_passed:
        console.print("\n[green bold]All repos satisfy SLSA L3 requirements.[/green bold]")
    else:
        failed = sum(1 for r in reports if not r.passed)
        console.print(f"\n[red bold]{failed} repo(s) have SLSA L3 gaps.[/red bold]")
        raise typer.Exit(code=1)
