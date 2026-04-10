# SPDX-License-Identifier: Apache-2.0
"""Tests for compliance-config, packs, and config overlay (rune-docs#227, #229)."""

from __future__ import annotations

from pathlib import Path

import pytest

import rune_audit.sr2.packs as packs_module
from rune_audit.sr2.compliance_config import (
    compliance_config_template,
    default_compliance_config,
    load_compliance_config,
    try_load_compliance_config,
)
from rune_audit.sr2.engine import run_pack_verification
from rune_audit.sr2.models import InspectStatus
from rune_audit.sr2.packs import (
    BUILTIN_PACK_STEMS,
    PackDocument,
    PackMeta,
    PackRequirementRow,
    catalog_specs_for_ids,
    ids_for_pack,
    load_builtin_pack,
)


def test_default_compliance_config_rune_defaults() -> None:
    d = default_compliance_config()
    assert d.project.name == "RUNE"
    names = {r.name for r in d.project.repos}
    assert "rune" in names
    assert "rune-audit" in names


def test_compliance_config_roundtrip(tmp_path: Path) -> None:
    text = compliance_config_template(
        project_name="demo",
        github_org="acme",
        repo_names=["core", "charts"],
        standard="iec-62443-4-1",
        pack="builtin://slsa-l3",
    )
    p = tmp_path / "cc.yaml"
    p.write_text(text, encoding="utf-8")
    loaded = load_compliance_config(p)
    assert loaded.project.github_org == "acme"
    assert [r.name for r in loaded.project.repos] == ["core", "charts"]
    assert "slsa" in loaded.compliance.pack


def test_try_load_missing_returns_defaults(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    d = try_load_compliance_config()
    assert d.project.name == "RUNE"


def test_try_load_reads_compliance_config_yaml(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    text = compliance_config_template(
        project_name="acme",
        github_org="acme-corp",
        repo_names=["svc"],
    )
    (tmp_path / "compliance-config.yaml").write_text(text, encoding="utf-8")
    d = try_load_compliance_config()
    assert d.project.name == "acme"
    assert d.project.github_org == "acme-corp"


def test_audit_config_merges_compliance_repos(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    text = compliance_config_template(
        project_name="p",
        github_org="o",
        repo_names=["alpha", "beta"],
    )
    (tmp_path / "compliance-config.yaml").write_text(text, encoding="utf-8")
    from rune_audit.config import AuditConfig

    cfg = AuditConfig.load()
    assert cfg.repos == ["alpha", "beta"]


def test_all_builtin_packs_load() -> None:
    for stem in BUILTIN_PACK_STEMS:
        doc = load_builtin_pack(stem)
        assert doc.pack.name
        assert len(doc.requirements) >= 1


def test_load_builtin_pack_rejects_non_mapping(monkeypatch) -> None:
    packs_module.load_builtin_pack.cache_clear()
    try:
        monkeypatch.setattr(packs_module.yaml, "safe_load", lambda _stream: [])
        with pytest.raises(ValueError, match="mapping"):
            packs_module.load_builtin_pack("slsa-l3")
    finally:
        packs_module.load_builtin_pack.cache_clear()


def test_catalog_specs_for_ids_subset() -> None:
    ids = frozenset({"SR-Q-001", "SR-Q-099"})
    specs = catalog_specs_for_ids(ids)
    assert len(specs) == 1
    assert specs[0].id == "SR-Q-001"


def test_ids_for_pack_iec_subset() -> None:
    s = ids_for_pack("iec-62443-ml4")
    assert "SR-Q-004" in s
    assert "SR-Q-008" in s


def test_load_compliance_config_empty_file_defaults(tmp_path: Path) -> None:
    p = tmp_path / "empty.yaml"
    p.write_text("", encoding="utf-8")
    d = load_compliance_config(p)
    assert d.project.name == "RUNE"


def test_ids_for_pack_unknown_falls_back_to_full_catalog() -> None:
    s = ids_for_pack("not-a-builtin-pack-id")
    assert "SR-Q-001" in s
    assert "SR-Q-036" in s


def test_ids_for_pack_full_synonym_matches_catalog() -> None:
    assert ids_for_pack("full") == ids_for_pack("iec-62443-sr2")
    assert ids_for_pack("all") == ids_for_pack("full")


def test_pack_verification_passes_threshold_to_stdlib_inspector(tmp_path: Path, monkeypatch) -> None:
    """Pack YAML `threshold` is forwarded on RequirementSpec for stdlib inspectors."""
    fake = PackDocument(
        pack=PackMeta(name="t", standard="x"),
        requirements=[
            PackRequirementRow(
                id="stdlib.license_compliance",
                title="License",
                priority="P2",
                inspector="stdlib.license_compliance",
                threshold={"min_license_bytes": 80},
            )
        ],
    )
    monkeypatch.setattr("rune_audit.sr2.engine.load_builtin_pack", lambda _stem: fake)
    (tmp_path / "LICENSE").write_text("x" * 40, encoding="utf-8")
    report = run_pack_verification(root=tmp_path, pack_stem="slsa-l3")
    assert len(report.results) == 1
    assert report.results[0].status == InspectStatus.FAIL
