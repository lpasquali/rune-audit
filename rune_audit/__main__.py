# SPDX-License-Identifier: Apache-2.0
"""Entry point for ``rune-audit`` console script."""

from __future__ import annotations

from rune_audit.cli.app import app


def main() -> None:
    """Entry point for the ``rune-audit`` console script installed by pip."""
    app()


if __name__ == "__main__":
    main()
