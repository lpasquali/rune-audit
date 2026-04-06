"""Tests for SBOM data models."""

from __future__ import annotations

from typing import Any

from rune_audit.models.sbom import SBOMComponent, SBOMDocument, SBOMToolMetadata


def test_sbom_component_creation() -> None:
    """SBOMComponent can be created with all fields."""
    comp = SBOMComponent(
        bom_ref="pkg:pypi/typer@0.9.0",
        type="library",
        name="typer",
        version="0.9.0",
        purl="pkg:pypi/typer@0.9.0",
        licenses=["MIT"],
    )
    assert comp.name == "typer"
    assert comp.version == "0.9.0"
    assert comp.licenses == ["MIT"]


def test_sbom_component_defaults() -> None:
    """SBOMComponent defaults are sensible."""
    comp = SBOMComponent(name="test")
    assert comp.bom_ref == ""
    assert comp.component_type == "library"
    assert comp.version == ""
    assert comp.purl == ""
    assert comp.licenses == []


def test_sbom_tool_metadata() -> None:
    """SBOMToolMetadata stores tool info."""
    tool = SBOMToolMetadata(vendor="anchore", name="syft", version="1.17.0")
    assert tool.vendor == "anchore"
    assert tool.name == "syft"


def test_sbom_document_from_cyclonedx(sample_sbom: dict[str, Any]) -> None:
    """SBOMDocument.from_cyclonedx parses a valid CycloneDX JSON."""
    doc = SBOMDocument.from_cyclonedx(sample_sbom, source_repo="lpasquali/rune")
    assert doc.bom_format == "CycloneDX"
    assert doc.spec_version == "1.5"
    assert len(doc.components) == 3
    assert doc.components[0].name == "typer"
    assert doc.source_repo == "lpasquali/rune"
    assert len(doc.tools) == 1
    assert doc.tools[0].name == "syft"
    assert doc.timestamp is not None


def test_sbom_document_from_cyclonedx_empty() -> None:
    """SBOMDocument.from_cyclonedx handles empty data."""
    doc = SBOMDocument.from_cyclonedx({})
    assert doc.bom_format == "CycloneDX"
    assert len(doc.components) == 0
    assert len(doc.tools) == 0
    assert doc.timestamp is None


def test_sbom_document_from_cyclonedx_old_tools_format() -> None:
    """SBOMDocument.from_cyclonedx handles pre-1.5 tools array."""
    data: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "tools": [
                {"vendor": "anchore", "name": "syft", "version": "0.90.0"}
            ]
        },
        "components": [],
    }
    doc = SBOMDocument.from_cyclonedx(data)
    assert len(doc.tools) == 1
    assert doc.tools[0].version == "0.90.0"


def test_sbom_component_license_from_name() -> None:
    """SBOMDocument.from_cyclonedx extracts license names when no SPDX id."""
    data: dict[str, Any] = {
        "components": [
            {
                "name": "pkg",
                "licenses": [{"license": {"name": "Apache License 2.0"}}],
            }
        ]
    }
    doc = SBOMDocument.from_cyclonedx(data)
    assert doc.components[0].licenses == ["Apache License 2.0"]
