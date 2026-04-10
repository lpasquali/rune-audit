# SPDX-License-Identifier: Apache-2.0
"""Standard inspector implementations (rune-docs#230)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rune_audit.sr2.registry import InspectorRegistry


def register_stdlib_inspectors(reg: InspectorRegistry) -> None:
    """Register all ``stdlib.*`` inspectors (idempotent if called twice — overwrites same ids)."""
    from . import (
        container_signing,
        dependabot_config,
        dockerfile_security,
        github_actions_pinning,
        go_coverage,
        helm_security_context,
        license_compliance,
        network_policy_presence,
        python_coverage,
        rbac_least_privilege,
        sast_coverage,
        sbom_completeness,
        secret_scanning,
        slsa_verification,
        vulnerability_scanning,
    )

    for mod in (
        python_coverage,
        go_coverage,
        helm_security_context,
        dockerfile_security,
        github_actions_pinning,
        dependabot_config,
        sbom_completeness,
        slsa_verification,
        secret_scanning,
        sast_coverage,
        license_compliance,
        vulnerability_scanning,
        container_signing,
        network_policy_presence,
        rbac_least_privilege,
    ):
        mod.register(reg)
