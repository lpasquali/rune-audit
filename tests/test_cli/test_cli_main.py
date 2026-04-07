# SPDX-License-Identifier: Apache-2.0
"""Tests for rune-audit CLI."""

from __future__ import annotations

from typer.testing import CliRunner

from rune_audit import __version__
from rune_audit.cli.app import app

runner = CliRunner()


def test_version_flag() -> None:
    """--version prints version and exits 0."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_version_short_flag() -> None:
    """-V prints version and exits 0."""
    result = runner.invoke(app, ["-V"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_no_args_shows_help() -> None:
    """No arguments shows help text (exit code 0 from Typer no_args_is_help)."""
    result = runner.invoke(app, [])
    # Typer with no_args_is_help=True may exit with 0 or 2 depending on version
    assert result.exit_code in (0, 2)
    assert "Usage" in result.output or "rune-audit" in result.output.lower()


def test_info_command() -> None:
    """info command shows version and status."""
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_help_flag() -> None:
    """--help prints help and exits 0."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "rune-audit" in result.output.lower() or "Usage" in result.output
