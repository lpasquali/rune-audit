# SPDX-License-Identifier: Apache-2.0
"""SBOM (Software Bill of Materials) evidence models.

Parses CycloneDX JSON format as produced by Syft.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SBOMComponent(BaseModel):
    """A single component in an SBOM."""

    bom_ref: str = Field(default="", description="BOM reference identifier")
    component_type: str = Field(default="library", alias="type", description="Component type (library, framework)")
    name: str = Field(description="Component name")
    version: str = Field(default="", description="Component version")
    purl: str = Field(default="", description="Package URL (purl) identifier")
    licenses: list[str] = Field(default_factory=list, description="SPDX license identifiers")

    model_config = {"populate_by_name": True}


class SBOMToolMetadata(BaseModel):
    """Metadata about the SBOM generation tool."""

    vendor: str = Field(default="", description="Tool vendor")
    name: str = Field(default="", description="Tool name")
    version: str = Field(default="", description="Tool version")


class SBOMDocument(BaseModel):
    """A CycloneDX SBOM document."""

    bom_format: str = Field(default="CycloneDX", alias="bomFormat", description="BOM format identifier")
    spec_version: str = Field(default="", alias="specVersion", description="CycloneDX spec version")
    serial_number: str = Field(default="", alias="serialNumber", description="Unique serial number")
    version: int = Field(default=1, description="BOM version")
    components: list[SBOMComponent] = Field(default_factory=list, description="Components in the BOM")
    tools: list[SBOMToolMetadata] = Field(default_factory=list, description="Tools used to generate the BOM")
    timestamp: datetime | None = Field(default=None, description="Generation timestamp")
    source_repo: str = Field(default="", description="Source repository")

    model_config = {"populate_by_name": True}

    @classmethod
    def from_cyclonedx(cls, data: dict[str, Any], source_repo: str = "") -> SBOMDocument:
        """Parse a CycloneDX JSON document into an SBOMDocument.

        Args:
            data: Parsed CycloneDX JSON dictionary.
            source_repo: Repository the SBOM was generated from.

        Returns:
            Parsed SBOMDocument instance.
        """
        components: list[SBOMComponent] = []
        for comp in data.get("components", []):
            licenses: list[str] = []
            for lic_entry in comp.get("licenses", []):
                if "license" in lic_entry:
                    lic = lic_entry["license"]
                    if "id" in lic:
                        licenses.append(lic["id"])
                    elif "name" in lic:
                        licenses.append(lic["name"])
            components.append(
                SBOMComponent(
                    bom_ref=comp.get("bom-ref", ""),
                    type=comp.get("type", "library"),
                    name=comp.get("name", ""),
                    version=comp.get("version", ""),
                    purl=comp.get("purl", ""),
                    licenses=licenses,
                )
            )

        tools: list[SBOMToolMetadata] = []
        metadata = data.get("metadata", {})
        raw_tools = metadata.get("tools", [])
        # CycloneDX 1.5+ uses {"tools": {"components": [...]}}
        if isinstance(raw_tools, dict):
            raw_tools = raw_tools.get("components", [])
        for tool in raw_tools:
            tools.append(
                SBOMToolMetadata(
                    vendor=tool.get("vendor", tool.get("author", "")),
                    name=tool.get("name", ""),
                    version=tool.get("version", ""),
                )
            )

        timestamp = None
        ts_str = metadata.get("timestamp")
        if ts_str:
            timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

        return cls(
            bomFormat=data.get("bomFormat", "CycloneDX"),
            specVersion=data.get("specVersion", ""),
            serialNumber=data.get("serialNumber", ""),
            version=data.get("version", 1),
            components=components,
            tools=tools,
            timestamp=timestamp,
            source_repo=source_repo,
        )
