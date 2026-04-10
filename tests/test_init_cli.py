# SPDX-License-Identifier: Apache-2.0
"""CLI: ``rune-audit init`` (rune-docs#231)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from rune_audit.cli.app import app
from rune_audit.cli.init_cmd import suggest_pack_for_root


def test_suggest_pack_for_root(tmp_path: Path) -> None:
    assert suggest_pack_for_root(tmp_path) == "iec-62443-ml4"
    (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: x\n", encoding="utf-8")
    assert suggest_pack_for_root(tmp_path) == "cis-kubernetes"


def test_init_noninteractive_writes_compliance_config(tmp_path: Path) -> None:
    out = tmp_path / "compliance-config.yaml"
    r = CliRunner().invoke(
        app,
        [
            "init",
            "-y",
            "--org",
            "acme",
            "--repos",
            "core,api",
            "--no-project-file",
            "-o",
            str(out),
        ],
    )
    assert r.exit_code == 0, r.output
    text = out.read_text(encoding="utf-8")
    assert "acme" in text
    assert "core" in text
    from rune_audit.sr2.compliance_config import load_compliance_config

    load_compliance_config(out)
