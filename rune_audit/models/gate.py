"""Quality gate result models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class GateStatus(str, Enum):
    """Quality gate status."""

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    PENDING = "pending"


class GateResult(BaseModel):
    """A single quality gate result from a CI workflow."""

    gate_name: str = Field(description="Gate name")
    status: GateStatus = Field(description="Gate status")
    workflow_run_id: int = Field(default=0, description="Workflow run ID")
    job_id: int = Field(default=0, description="Job ID")
    timestamp: datetime | None = Field(default=None, description="Completion timestamp")
    source_repo: str = Field(default="", description="Source repository")
    workflow_name: str = Field(default="", description="Workflow name")
    conclusion: str = Field(default="", description="Raw conclusion string")
    html_url: str = Field(default="", description="URL to the workflow run")

    @classmethod
    def from_github_job(
        cls,
        job_data: dict[str, object],
        source_repo: str = "",
        workflow_run_id: int = 0,
        workflow_name: str = "",
    ) -> GateResult:
        """Parse a GitHub Actions job into a GateResult."""
        conclusion = str(job_data.get("conclusion", "") or "")
        status_map: dict[str, GateStatus] = {
            "success": GateStatus.PASS,
            "failure": GateStatus.FAIL,
            "skipped": GateStatus.SKIP,
            "cancelled": GateStatus.SKIP,
        }
        status = status_map.get(conclusion, GateStatus.PENDING)
        timestamp = None
        completed_at = job_data.get("completed_at")
        if completed_at and isinstance(completed_at, str):
            timestamp = datetime.fromisoformat(
                completed_at.replace("Z", "+00:00")
            )
        return cls(
            gate_name=str(job_data.get("name", "")),
            status=status,
            workflow_run_id=workflow_run_id,
            job_id=int(job_data.get("id", 0)),
            timestamp=timestamp,
            source_repo=source_repo,
            workflow_name=workflow_name,
            conclusion=conclusion,
            html_url=str(job_data.get("html_url", "")),
        )
