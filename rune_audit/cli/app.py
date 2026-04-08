# SPDX-License-Identifier: Apache-2.0
"""Main Typer application for rune-audit CLI.

Registers all command groups and provides the ``rune-audit`` entry point.
"""

from __future__ import annotations

import typer

from rune_audit import __version__
from rune_audit.cli.collect import collect_app
from rune_audit.cli.compliance import compliance_app
from rune_audit.cli.config_cmd import config_app
from rune_audit.cli.rekor_cmd import rekor_app
from rune_audit.cli.report import report_app
from rune_audit.cli.slsa_cmd import slsa_app
from rune_audit.cli.tpm2_cmd import tpm2_app
from rune_audit.cli.vex import vex_app

app = typer.Typer(
    name="rune-audit",
    help="RUNE Audit — compliance evidence collection and verification.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def _version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        typer.echo(f"rune-audit {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: bool = typer.Option(  # noqa: B008
        False,
        "--version",
        "-V",
        help="Print version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """RUNE Audit — IEC 62443 compliance and SLSA provenance verification."""


# Register sub-command groups
app.add_typer(collect_app, name="collect", help="Gather evidence from all repos.")
app.add_typer(vex_app, name="vex", help="VEX document management.")
app.add_typer(compliance_app, name="compliance", help="Compliance reporting.")
app.add_typer(slsa_app, name="slsa", help="SLSA verification.")
app.add_typer(report_app, name="report", help="Generate reports.")
app.add_typer(config_app, name="config", help="Show configuration.")
app.add_typer(tpm2_app, name="tpm2", help="TPM2 attestation collection.")


@app.command()
def info() -> None:
    """Show audit service information."""
    typer.echo(f"rune-audit {__version__}")
    typer.echo("Status: CLI active — collectors and verifiers available")
