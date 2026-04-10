# SPDX-License-Identifier: Apache-2.0
"""Requirement pack loading (rune-docs#229)."""

from __future__ import annotations

import importlib.resources as resources
from functools import lru_cache

import yaml
from pydantic import BaseModel, Field

from rune_audit.sr2.catalog import iter_requirements
from rune_audit.sr2.models import RequirementSpec

IEC_62443_SR2: frozenset[str] = frozenset(f"SR-Q-{i:03d}" for i in range(1, 37))

BUILTIN_PACK_STEMS: frozenset[str] = frozenset(
    ("iec-62443-ml4", "slsa-l3", "cis-kubernetes", "nist-ssdf", "owasp-asvs"),
)


class PackMeta(BaseModel):
    name: str
    standard: str
    version: str = "1.0"


class PackRequirementRow(BaseModel):
    id: str
    title: str
    category: str = ""
    priority: str = "P2"
    inspector: str = "builtin://stub"


class PackDocument(BaseModel):
    pack: PackMeta
    requirements: list[PackRequirementRow] = Field(default_factory=list)


@lru_cache(maxsize=16)
def load_builtin_pack(pack_stem: str) -> PackDocument:
    """Load a shipped pack YAML from ``rune_audit.sr2.builtin_packs``."""
    if pack_stem not in BUILTIN_PACK_STEMS:
        msg = f"unknown pack {pack_stem!r}; expected one of {sorted(BUILTIN_PACK_STEMS)}"
        raise ValueError(msg)
    pkg = resources.files("rune_audit.sr2.builtin_packs")
    path = pkg.joinpath(f"{pack_stem}.yaml")
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict):
        msg = "pack file must be a mapping"
        raise ValueError(msg)
    return PackDocument.model_validate(raw)


def ids_for_pack(pack_id: str) -> frozenset[str]:
    """Requirement ids included in a named pack (builtin YAML or full SR-Q catalog)."""
    if pack_id in BUILTIN_PACK_STEMS:
        return frozenset(r.id for r in load_builtin_pack(pack_id).requirements)
    if pack_id in ("iec-62443-sr2", "full", "all"):
        return IEC_62443_SR2
    return IEC_62443_SR2


def catalog_specs_for_ids(ids: frozenset[str]) -> tuple[RequirementSpec, ...]:
    """Filter built-in SR-Q catalog rows by id; unknown ids are skipped."""
    by_id = {s.id: s for s in iter_requirements()}
    return tuple(by_id[i] for i in sorted(ids) if i in by_id)
