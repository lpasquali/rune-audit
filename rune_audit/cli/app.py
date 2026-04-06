"""Typer application definition for rune-audit CLI."""

from __future__ import annotations

import typer

from rune_audit import __version__

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


@app.command()
def info() -> None:
    """Show audit service information."""
    typer.echo(f"rune-audit {__version__}")
    typer.echo("Status: scaffolding — no collectors active yet")
