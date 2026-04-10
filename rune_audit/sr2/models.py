# SPDX-License-Identifier: Apache-2.0
"""Pydantic models for SR-2 verification."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Priority(StrEnum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"


class InspectStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"
    SKIPPED = "skipped"


class RequirementSpec(BaseModel):
    """One row from the quantitative requirements catalog."""

    id: str = Field(..., description="Identifier e.g. SR-Q-004")
    title: str
    priority: Priority


class InspectResult(BaseModel):
    requirement_id: str
    status: InspectStatus
    detail: str = ""


class VerifyReport(BaseModel):
    results: list[InspectResult]
    root: str | None = None
