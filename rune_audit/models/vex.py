"""VEX (Vulnerability Exploitability eXchange) document models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class VEXStatus(str, Enum):
    """VEX statement status values per OpenVEX spec."""

    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class VEXJustification(str, Enum):
    """VEX justification values for not_affected status."""

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


class VEXProduct(BaseModel):
    """A product reference in a VEX statement."""

    product_id: str = Field(alias="@id", description="Product identifier")

    model_config = {"populate_by_name": True}


class VEXStatement(BaseModel):
    """A single VEX statement about a vulnerability."""

    vulnerability_name: str = Field(description="CVE ID or vulnerability name")
    products: list[VEXProduct] = Field(default_factory=list)
    status: VEXStatus = Field(description="VEX status")
    justification: VEXJustification | None = Field(
        default=None, description="Justification (required for not_affected)"
    )
    impact_statement: str = Field(default="", description="Impact description")
    action_statement: str = Field(default="", description="Action to take")

    @classmethod
    def from_openvex(cls, data: dict[str, Any]) -> VEXStatement:
        """Parse a single OpenVEX statement."""
        vuln = data.get("vulnerability", {})
        vuln_name = vuln.get("name", "") if isinstance(vuln, dict) else str(vuln)
        products = []
        for prod in data.get("products", []):
            if isinstance(prod, dict) and "@id" in prod:
                products.append(VEXProduct(**prod))
        justification = None
        just_str = data.get("justification")
        if just_str:
            try:
                justification = VEXJustification(just_str)
            except ValueError:
                pass
        return cls(
            vulnerability_name=vuln_name,
            products=products,
            status=VEXStatus(data.get("status", "under_investigation")),
            justification=justification,
            impact_statement=data.get("impact_statement", ""),
            action_statement=data.get("action_statement", ""),
        )


class VEXDocument(BaseModel):
    """An OpenVEX document."""

    context: str = Field(alias="@context", description="OpenVEX context URI")
    doc_id: str = Field(alias="@id", description="Document identifier")
    author: str = Field(description="Document author")
    role: str = Field(default="", description="Author role")
    timestamp: datetime = Field(description="Document timestamp")
    version: int = Field(default=1, description="Document version")
    statements: list[VEXStatement] = Field(default_factory=list)
    source_repo: str = Field(default="", description="Source repository")

    model_config = {"populate_by_name": True}

    @classmethod
    def from_openvex(
        cls, data: dict[str, Any], source_repo: str = "",
    ) -> VEXDocument:
        """Parse an OpenVEX JSON document."""
        required = {
            "@context", "@id", "author", "timestamp", "version", "statements",
        }
        missing = required - set(data.keys())
        if missing:
            raise ValueError(
                f"Missing required OpenVEX fields: {sorted(missing)}"
            )
        statements = [
            VEXStatement.from_openvex(s)
            for s in data.get("statements", [])
        ]
        ts = data["timestamp"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return cls(
            **{"@context": data["@context"], "@id": data["@id"]},
            author=data["author"],
            role=data.get("role", ""),
            timestamp=ts,
            version=data["version"],
            statements=statements,
            source_repo=source_repo,
        )

    def get_suppressed_cves(self) -> set[str]:
        """Return CVE IDs that are suppressed (not_affected or fixed)."""
        return {
            s.vulnerability_name
            for s in self.statements
            if s.status in (VEXStatus.NOT_AFFECTED, VEXStatus.FIXED)
        }

    def get_affected_cves(self) -> set[str]:
        """Return CVE IDs that are still affected."""
        return {
            s.vulnerability_name
            for s in self.statements
            if s.status == VEXStatus.AFFECTED
        }

    @property
    def statement_count(self) -> int:
        """Number of statements in this document."""
        return len(self.statements)
