"""Tests for configuration loading."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import yaml

from rune_audit.config import DEFAULT_OUTPUT_DIR, DEFAULT_REPOS, AuditConfig


class TestAuditConfig:
    def test_defaults(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "RUNE_AUDIT_GITHUB_TOKEN": "",
                "RUNE_AUDIT_REPOS": "",
                "RUNE_AUDIT_OUTPUT_DIR": "",
            },
            clear=False,
        ):
            cfg = AuditConfig.load("/nonexistent/path.yaml")
            assert cfg.repos == DEFAULT_REPOS
            assert cfg.output_dir == DEFAULT_OUTPUT_DIR
            assert cfg.github_token == ""

    @patch.dict(
        "os.environ",
        {
            "RUNE_AUDIT_GITHUB_TOKEN": "tok123",
            "RUNE_AUDIT_REPOS": "rune,rune-ui",
            "RUNE_AUDIT_OUTPUT_DIR": "/tmp/out",
        },
    )
    def test_from_env(self) -> None:
        cfg = AuditConfig.load("/nonexistent.yaml")
        assert cfg.github_token == "tok123"
        assert cfg.repos == ["rune", "rune-ui"]
        assert cfg.output_dir == "/tmp/out"

    def test_from_yaml(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(
                {
                    "repos": ["rune"],
                    "output_dir": "/custom",
                    "output_format": "json",
                },
                f,
            )
            f.flush()
            with patch.dict(
                "os.environ",
                {
                    "RUNE_AUDIT_GITHUB_TOKEN": "",
                    "RUNE_AUDIT_REPOS": "",
                    "RUNE_AUDIT_OUTPUT_DIR": "",
                },
                clear=False,
            ):
                cfg = AuditConfig.load(f.name)
                assert cfg.repos == ["rune"]
                assert cfg.output_dir == "/custom"
                assert cfg.output_format == "json"

    def test_yaml_auto_discover(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "rune-audit.yaml"
            yaml_path.write_text(yaml.dump({"repos": ["test-repo"]}))
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                with patch.dict(
                    "os.environ",
                    {
                        "RUNE_AUDIT_GITHUB_TOKEN": "",
                        "RUNE_AUDIT_REPOS": "",
                        "RUNE_AUDIT_OUTPUT_DIR": "",
                    },
                    clear=False,
                ):
                    cfg = AuditConfig.load()
                    assert cfg.repos == ["test-repo"]
            finally:
                os.chdir(old_cwd)

    def test_empty_yaml(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("")
            f.flush()
            with patch.dict(
                "os.environ",
                {
                    "RUNE_AUDIT_GITHUB_TOKEN": "",
                    "RUNE_AUDIT_REPOS": "",
                    "RUNE_AUDIT_OUTPUT_DIR": "",
                },
                clear=False,
            ):
                cfg = AuditConfig.load(f.name)
                assert cfg.repos == DEFAULT_REPOS

    @patch.dict("os.environ", {"RUNE_AUDIT_REPOS": " rune , rune-ui , "})
    def test_repos_whitespace_handling(self) -> None:
        cfg = AuditConfig.load("/nonexistent.yaml")
        assert cfg.repos == ["rune", "rune-ui"]
