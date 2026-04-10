# SPDX-License-Identifier: Apache-2.0
"""Named requirement packs (SLSA, CIS, custom) — EPIC #229 foundation."""

from __future__ import annotations

# Pack ids are stable labels for `rune-audit sr2 verify --pack ...` (future).

IEC_62443_SR2: frozenset[str] = frozenset(f"SR-Q-{i:03d}" for i in range(1, 37))


def ids_for_pack(pack_id: str) -> frozenset[str]:
    """Return requirement ids for a pack.

    Today only the full IEC 62443 SR-2 catalog (36 ids) is defined; *pack_id* is reserved.
    """
    _ = pack_id
    return IEC_62443_SR2
