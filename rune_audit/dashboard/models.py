# SPDX-License-Identifier: Apache-2.0
"""Dashboard data models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class RepoStatus(BaseModel):
    """Status of a repository workflow run."""

    repo: str
    workflow: str
    status: str  # success, failure, pending
    run_url: str = ""
    updated_at: datetime | None = None


class RepoCoverage(BaseModel):
    """Coverage metrics for a repository."""

    repo: str
    language: str = "python"
    coverage_pct: float = 0.0
    floor: float = 97.0


class RepoAlerts(BaseModel):
    """Security alert counts for a repository."""

    repo: str
    dependabot_open: int = 0
    code_scanning_open: int = 0
    critical_cves: int = 0


class DashboardData(BaseModel):
    """Aggregated dashboard data across all repos."""

    collected_at: datetime = Field(default_factory=datetime.utcnow)
    repos: list[RepoStatus] = Field(default_factory=list)
    coverage: list[RepoCoverage] = Field(default_factory=list)
    alerts: list[RepoAlerts] = Field(default_factory=list)
