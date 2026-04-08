# SPDX-License-Identifier: Apache-2.0
"""Data models for TLA+ formal verification results."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field


class CheckResult(BaseModel):
    """Result of running a TLA+ specification through TLC."""

    spec: str = Field(description="Specification name")
    passed: bool = Field(description="Whether all invariants held")
    states_found: int = Field(default=0, description="Total states explored")
    distinct_states: int = Field(default=0, description="Distinct states found")
    violations: list[str] = Field(default_factory=list, description="Invariant violations found")
    duration_seconds: float = Field(default=0.0, description="Execution time in seconds")


class SpecInfo(BaseModel):
    """Metadata about an available TLA+ specification."""

    name: str = Field(description="Specification name (without .tla extension)")
    path: Path = Field(description="Absolute path to the .tla file")
    description: str = Field(default="", description="Brief description extracted from spec header")
