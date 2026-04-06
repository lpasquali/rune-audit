"""VEX (Vulnerability Exploitability eXchange) document models.

Models for OpenVEX documents as used in the RUNE ecosystem.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class VEXStatus(str, Enum):
    """VEX statement status values per OpenVEX spec."""

    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class VEXStatement(BaseModel):
    """A single VEX statement about a vulnerability."""

    vulnerability_id: str = Field(default="", description="CVE identifier")
    status: VEXStatus = Field(description="VEX status")
    justification: str = Field(default="", description="Justification for not_affected")
    impact_statement: str = Field(default="", description="Impact description")


class VEXDocument(BaseModel):
    """An OpenVEX document."""

    context: str = Field(default="", alias="@context", description="OpenVEX context URI")
    doc_id: str = Field(default="", alias="@id", description="Document identifier")
    author: str = Field(default="", description="Document author")
    version: int = Field(default=1, description="Document version")
    statements: list[VEXStatement] = Field(default_factory=list, description="VEX statements")

    model_config = {"populate_by_name": True}

    def get_suppressed_cves(self) -> set[str]:
        """Return CVE IDs that are suppressed (not_affected) by this document."""
        return {s.vulnerability_id for s in self.statements if s.status == VEXStatus.NOT_AFFECTED}
