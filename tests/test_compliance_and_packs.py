# SPDX-License-Identifier: Apache-2.0
"""Tests for compliance-config, packs, and config overlay (rune-docs#227, #229)."""

from __future__ import annotations

from pathlib import Path

from rune_audit.sr2.compliance_config import (
    compliance_config_template,
    default_compliance_config,
    load_compliance_config,
    try_load_compliance_config,
)
from rune_audit.sr2.packs import BUILTIN_PACK_STEMS, catalog_specs_for_ids, ids_for_pack, load_builtin_pack


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


def test_catalog_specs_for_ids_subset() -> None:
    ids = frozenset({"SR-Q-001", "SR-Q-099"})
    specs = catalog_specs_for_ids(ids)
    assert len(specs) == 1
    assert specs[0].id == "SR-Q-001"


def test_ids_for_pack_iec_subset() -> None:
    s = ids_for_pack("iec-62443-ml4")
    assert "SR-Q-004" in s
    assert "SR-Q-008" in s
