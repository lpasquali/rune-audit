# SPDX-License-Identifier: Apache-2.0
"""`compliance-config.yaml` schema and loader (rune-docs#227)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class ProjectRepoEntry(BaseModel):
    """Repository entry under ``project.repos``."""

    name: str
    type: str = "python"


class ProjectSection(BaseModel):
    name: str = "RUNE"
    github_org: str = "lpasquali"
    repos: list[ProjectRepoEntry] = Field(default_factory=list)


class ComplianceSection(BaseModel):
    standard: str = "iec-62443-4-1"
    pack: str = "builtin://iec-62443-ml4"
    requirements_override: list[dict[str, Any]] = Field(default_factory=list)


class EvidenceGateRef(BaseModel):
    name: str = ""
    pattern: str = ""


class EvidenceSection(BaseModel):
    gates: list[EvidenceGateRef] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)
    patterns: list[str] = Field(default_factory=list)


class ComplianceConfigFile(BaseModel):
    """Top-level ``compliance-config.yaml`` (v1)."""

    version: int = Field(1, ge=1)
    project: ProjectSection = Field(default_factory=ProjectSection)
    compliance: ComplianceSection = Field(default_factory=ComplianceSection)
    evidence: EvidenceSection = Field(default_factory=EvidenceSection)


def default_compliance_config() -> ComplianceConfigFile:
    """RUNE defaults when no file is present."""
    from rune_audit.config import DEFAULT_REPOS

    return ComplianceConfigFile(
        version=1,
        project=ProjectSection(
            name="RUNE",
            github_org="lpasquali",
            repos=[ProjectRepoEntry(name=r) for r in DEFAULT_REPOS],
        ),
        compliance=ComplianceSection(),
        evidence=EvidenceSection(),
    )


def load_compliance_config(path: Path) -> ComplianceConfigFile:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if raw is None:
        return default_compliance_config()
    if not isinstance(raw, dict):
        msg = "compliance-config.yaml must be a mapping at the top level"
        raise ValueError(msg)
    return ComplianceConfigFile.model_validate(raw)


def resolve_project_repo_paths(cfg: ComplianceConfigFile, base: Path) -> list[tuple[str, Path]]:
    """Map ``project.repos[].name`` to ``base / name`` (rune-docs#212 matrix)."""
    out: list[tuple[str, Path]] = []
    for r in cfg.project.repos:
        if not r.name:
            continue
        out.append((r.name, (base / r.name).resolve()))
    return out


def try_load_compliance_config(path: Path | None = None) -> ComplianceConfigFile:
    """Load from *path* or ``./compliance-config.yaml``; fall back to RUNE defaults."""
    candidate = path or Path("compliance-config.yaml")
    if not candidate.exists():
        return default_compliance_config()
    return load_compliance_config(candidate)


def compliance_config_template(
    *,
    project_name: str,
    github_org: str,
    repo_names: list[str],
    standard: str = "iec-62443-4-1",
    pack: str = "builtin://iec-62443-ml4",
) -> str:
    """Serialized ``compliance-config.yaml`` for ``rune-audit init``."""
    import yaml

    cfg = ComplianceConfigFile(
        version=1,
        project=ProjectSection(
            name=project_name,
            github_org=github_org,
            repos=[ProjectRepoEntry(name=n.strip()) for n in repo_names if n.strip()],
        ),
        compliance=ComplianceSection(standard=standard, pack=pack),
        evidence=EvidenceSection(),
    )
    return yaml.safe_dump(cfg.model_dump(mode="python"), sort_keys=False, allow_unicode=True)
