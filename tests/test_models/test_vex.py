"""Tests for VEX document models."""

from typing import Any

import pytest

from rune_audit.models.vex import VEXDocument, VEXStatement, VEXStatus


def test_status_values():
    assert VEXStatus.NOT_AFFECTED.value == "not_affected"
    assert VEXStatus.UNDER_INVESTIGATION.value == "under_investigation"


def test_from_openvex():
    data = {
        "vulnerability": {"name": "CVE-X"},
        "products": [{"@id": "pkg:a"}],
        "status": "not_affected",
        "justification": "vulnerable_code_cannot_be_controlled_by_adversary",
        "impact_statement": "OK",
    }
    s = VEXStatement.from_openvex(data)
    assert s.vulnerability_name == "CVE-X" and s.status == VEXStatus.NOT_AFFECTED and len(s.products) == 1


def test_from_openvex_affected():
    s = VEXStatement.from_openvex(
        {"vulnerability": {"name": "X"}, "status": "affected", "impact_statement": "V", "action_statement": "F"}
    )
    assert s.status == VEXStatus.AFFECTED and s.action_statement == "F"


def test_from_openvex_string_vuln():
    assert (
        VEXStatement.from_openvex({"vulnerability": "CVE-X", "status": "under_investigation"}).vulnerability_name
        == "CVE-X"
    )


def test_from_openvex_invalid_just():
    assert (
        VEXStatement.from_openvex(
            {"vulnerability": {"name": "X"}, "status": "not_affected", "justification": "bad"}
        ).justification
        is None
    )


def test_from_openvex_no_products():
    assert VEXStatement.from_openvex({"vulnerability": {"name": "X"}, "status": "fixed"}).products == []


def test_from_openvex_invalid_product():
    assert (
        VEXStatement.from_openvex(
            {"vulnerability": {"name": "X"}, "status": "fixed", "products": [{"bad": "x"}]}
        ).products
        == []
    )


def test_vex_document(openvex_data: dict[str, Any]):
    doc = VEXDocument.from_openvex(openvex_data, source_repo="lpasquali/rune")
    assert doc.author == "lpasquali" and len(doc.statements) == 3 and doc.statement_count == 3


def test_vex_document_scaffolding(sample_openvex: dict[str, Any]):
    doc = VEXDocument.from_openvex(sample_openvex, source_repo="test")
    assert doc.author == "RUNE Project" and len(doc.statements) == 1


def test_get_suppressed(openvex_data: dict[str, Any]):
    assert "CVE-2005-2541" in VEXDocument.from_openvex(openvex_data).get_suppressed_cves()


def test_get_affected(openvex_data: dict[str, Any]):
    assert "CVE-2026-25679" in VEXDocument.from_openvex(openvex_data).get_affected_cves()


def test_missing_fields():
    with pytest.raises(ValueError, match="Missing required"):
        VEXDocument.from_openvex({"@context": "t", "author": "t"})


def test_parse_real_rune_vex():
    import json
    from pathlib import Path

    p = Path("/home/ubuntu/Devel/rune/.vex/permanent.openvex.json")
    if not p.exists():
        pytest.skip("not available")
    doc = VEXDocument.from_openvex(json.loads(p.read_text()), source_repo="lpasquali/rune")
    assert doc.author == "lpasquali" and len(doc.statements) > 0
