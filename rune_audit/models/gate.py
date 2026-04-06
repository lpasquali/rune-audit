"""Quality gate result models.

Models for CI quality gate pass/fail results.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class GateStatus(str, Enum):
    """Status of a quality gate."""

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"


class GateResult(BaseModel):
    """Result of a single quality gate check."""

    gate_name: str = Field(description="Name of the quality gate")
    status: GateStatus = Field(description="Gate result status")
    message: str = Field(default="", description="Human-readable result message")
    job_url: str = Field(default="", description="Link to the CI job")
