"""Tests for __main__ entry point."""

from __future__ import annotations

from unittest.mock import patch

from rune_audit.__main__ import main


def test_main_calls_app() -> None:
    """main() invokes the Typer app."""
    with patch("rune_audit.__main__.app") as mock_app:
        main()
        mock_app.assert_called_once()
