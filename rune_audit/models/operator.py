# SPDX-License-Identifier: Apache-2.0
"""Data models for rune-operator RuneBenchmark resources."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from datetime import datetime


class RunRecord(BaseModel):
    """A single RuneBenchmark custom resource record."""

    name: str = Field(description="RuneBenchmark resource name")
    namespace: str = Field(default="default", description="Kubernetes namespace")
    status: str = Field(default="Unknown", description="Current status (Pending, Running, Complete, Failed)")
    agent: str = Field(default="", description="Agent name used for the run")
    model: str = Field(default="", description="LLM model used")
    backend_type: str = Field(default="ollama", description="Backend type (ollama, openai, etc.)")
    result: dict | None = Field(default=None, description="Raw result data from the run")
    cost_estimation: dict | None = Field(default=None, description="Cost estimation data")
    created_at: datetime = Field(description="Resource creation timestamp")
    completed_at: datetime | None = Field(default=None, description="Completion timestamp")


class AuditEvent(BaseModel):
    """A single event in an audit trail."""

    timestamp: datetime = Field(description="Event timestamp")
    event_type: str = Field(description="Event type (e.g., Created, Running, Completed, Failed)")
    message: str = Field(default="", description="Human-readable event message")
    details: dict | None = Field(default=None, description="Additional event details")


class AuditTrail(BaseModel):
    """Full audit trail for a RuneBenchmark run."""

    run_name: str = Field(description="RuneBenchmark resource name")
    events: list[AuditEvent] = Field(default_factory=list, description="Ordered list of audit events")
    records: list[RunRecord] = Field(default_factory=list, description="Associated run records")
