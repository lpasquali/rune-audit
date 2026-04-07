# SPDX-License-Identifier: Apache-2.0
"""Configuration loading for rune-audit.

Reads settings from environment variables and optional ``rune-audit.yaml`` file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_REPOS: list[str] = [
    "rune",
    "rune-operator",
    "rune-ui",
    "rune-charts",
    "rune-docs",
    "rune-audit",
]

DEFAULT_OUTPUT_DIR = "./audit-output"


@dataclass
class AuditConfig:
    """Runtime configuration for rune-audit."""

    github_token: str = ""
    repos: list[str] = field(default_factory=lambda: list(DEFAULT_REPOS))
    output_dir: str = DEFAULT_OUTPUT_DIR
    output_format: str = "md"

    @classmethod
    def load(cls, config_path: str | None = None) -> AuditConfig:
        """Load config from env vars, then overlay with YAML file if present."""
        cfg = cls()

        # Environment variables
        cfg.github_token = os.environ.get("RUNE_AUDIT_GITHUB_TOKEN", "")
        repos_env = os.environ.get("RUNE_AUDIT_REPOS", "")
        if repos_env:
            cfg.repos = [r.strip() for r in repos_env.split(",") if r.strip()]
        output_dir = os.environ.get("RUNE_AUDIT_OUTPUT_DIR", "")
        if output_dir:
            cfg.output_dir = output_dir

        # YAML config overlay
        yaml_path = Path(config_path) if config_path else Path("rune-audit.yaml")
        if yaml_path.exists():
            with open(yaml_path) as fh:
                data = yaml.safe_load(fh)
            if isinstance(data, dict):
                if "repos" in data and isinstance(data["repos"], list):
                    cfg.repos = data["repos"]
                if "output_dir" in data and isinstance(data["output_dir"], str):
                    cfg.output_dir = data["output_dir"]
                if "output_format" in data and isinstance(data["output_format"], str):
                    cfg.output_format = data["output_format"]

        return cfg
