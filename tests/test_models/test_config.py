# SPDX-License-Identifier: Apache-2.0
"""Tests for configuration loading."""

from __future__ import annotations

import os
from pathlib import Path

from rune_audit.config import DEFAULT_REPOS, AuditConfig


def test_audit_config_defaults() -> None:
    """AuditConfig defaults are sensible."""
    config = AuditConfig()
    assert config.github_token == ""
    assert config.repos == list(DEFAULT_REPOS)
    assert config.output_dir == "./audit-output"
    assert config.output_format == "md"


def test_audit_config_load_defaults(monkeypatch: object) -> None:
    """AuditConfig.load returns defaults when no env vars or file exist."""

    monkeypatch.setattr(os, "environ", {})  # type: ignore[attr-defined]
    # Use a nonexistent path so no YAML is loaded
    config = AuditConfig.load("/nonexistent/config.yaml")
    assert config.repos == list(DEFAULT_REPOS)


def test_audit_config_load_from_env(monkeypatch: object) -> None:
    """AuditConfig.load reads from environment variables."""
    monkeypatch.setattr(
        os.environ,
        "get",
        lambda key, default="": {  # type: ignore[attr-defined]
            "RUNE_AUDIT_GITHUB_TOKEN": "test-token",
            "RUNE_AUDIT_REPOS": "repo-a, repo-b",
            "RUNE_AUDIT_OUTPUT_DIR": "/tmp/audit",
        }.get(key, default),
    )
    config = AuditConfig.load("/nonexistent/config.yaml")
    assert config.github_token == "test-token"
    assert config.repos == ["repo-a", "repo-b"]
    assert config.output_dir == "/tmp/audit"


def test_audit_config_load_from_yaml(tmp_path: Path) -> None:
    """AuditConfig.load reads from YAML file."""
    config_file = tmp_path / "rune-audit.yaml"
    config_file.write_text(
        "repos:\n  - lpasquali/rune\n  - lpasquali/rune-audit\noutput_dir: /custom/dir\noutput_format: json\n",
        encoding="utf-8",
    )
    config = AuditConfig.load(str(config_file))
    assert config.repos == ["lpasquali/rune", "lpasquali/rune-audit"]
    assert config.output_dir == "/custom/dir"
    assert config.output_format == "json"


def test_audit_config_load_empty_yaml(tmp_path: Path) -> None:
    """AuditConfig.load handles empty YAML file."""
    config_file = tmp_path / "rune-audit.yaml"
    config_file.write_text("", encoding="utf-8")
    config = AuditConfig.load(str(config_file))
    assert config.repos == list(DEFAULT_REPOS)


def test_audit_config_load_invalid_yaml_types(tmp_path: Path) -> None:
    """AuditConfig.load handles YAML with wrong types gracefully."""
    config_file = tmp_path / "rune-audit.yaml"
    config_file.write_text("repos: not-a-list\noutput_dir: 123\n", encoding="utf-8")
    config = AuditConfig.load(str(config_file))
    # repos should remain default since it's not a list
    assert config.repos == list(DEFAULT_REPOS)
