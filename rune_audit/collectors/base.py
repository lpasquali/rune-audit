# SPDX-License-Identifier: Apache-2.0
"""Base collector protocol."""

from __future__ import annotations

from typing import Protocol

from rune_audit.models.evidence import EvidenceBundle


class Collector(Protocol):
    """Protocol for evidence collectors."""

    def collect(self, repo: str, ref: str = "") -> EvidenceBundle:
        """Collect evidence from a source.

        Args:
            repo: Repository in owner/name format.
            ref: Git ref (branch, tag, or SHA).

        Returns:
            An EvidenceBundle with collected evidence items.
        """
        ...  # pragma: no cover
