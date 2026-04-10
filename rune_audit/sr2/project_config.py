# SPDX-License-Identifier: Apache-2.0
"""Config-driven project definitions for reusing rune-audit outside RUNE (EPIC #227)."""

from __future__ import annotations

from pathlib import Path  # noqa: TC003

import yaml
from pydantic import BaseModel, Field


class ProjectRepo(BaseModel):
    """One Git repository to scan."""

    name: str
    url: str = ""
    path: str = ""


class AuditProjectFile(BaseModel):
    """``.rune-audit-project.yaml`` schema (v1)."""

    version: int = Field(1, ge=1)
    name: str = "unnamed-project"
    repos: list[ProjectRepo] = Field(default_factory=list)


def load_project_file(path: Path) -> AuditProjectFile:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        msg = "project file must be a mapping at the top level"
        raise ValueError(msg)
    return AuditProjectFile.model_validate(raw)


def default_project_template() -> str:
    return (
        "# rune-audit external project definition (SR-2 / EPIC #227)\n"
        "version: 1\n"
        "name: my-oss-project\n"
        "repos:\n"
        "  - name: app\n"
        "    path: .\n"
    )
