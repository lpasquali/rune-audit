# SPDX-License-Identifier: Apache-2.0
"""Standard inspector implementations (rune-docs#230)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rune_audit.sr2.registry import InspectorRegistry


def register_stdlib_inspectors(reg: InspectorRegistry) -> None:
    """Register all ``stdlib.*`` inspectors (idempotent if called twice — overwrites same ids)."""
    from . import (
        api_server_security,
        container_signing,
        dependabot_config,
        dockerfile_security,
        github_actions_pinning,
        go_coverage,
        helm_audit_retention,
        helm_security_context,
        license_compliance,
        network_policy_presence,
        operator_security,
        python_coverage,
        rbac_least_privilege,
        sast_coverage,
        sbom_completeness,
        secret_scanning,
        slsa_verification,
        tls_security,
        vulnerability_scanning,
    )

    for mod in (
        api_server_security,
        operator_security,
        python_coverage,
        go_coverage,
        helm_audit_retention,
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
        tls_security,
    ):
        mod.register(reg)

    # SR-Q ID mapping (EPIC #211)
    # 100% of 36 requirements are now mapped to stdlib inspectors.
    _mapping = {
        "SR-Q-001": api_server_security._inspect_api_server,
        "SR-Q-002": api_server_security._inspect_api_server,
        "SR-Q-003": api_server_security._inspect_api_server,
        "SR-Q-004": api_server_security._inspect_api_server,
        "SR-Q-005": api_server_security._inspect_api_server,
        "SR-Q-006": helm_security_context._inspect,
        "SR-Q-007": api_server_security._inspect_api_server,
        "SR-Q-008": api_server_security._inspect_api_server,
        "SR-Q-009": operator_security._inspect_operator,
        "SR-Q-010": api_server_security._inspect_api_server,
        "SR-Q-011": api_server_security._inspect_driver_timeouts,
        "SR-Q-012": api_server_security._inspect_api_server,
        "SR-Q-013": helm_security_context._inspect,
        "SR-Q-014": helm_security_context._inspect,
        "SR-Q-015": tls_security._inspect,
        "SR-Q-016": api_server_security._inspect_api_server,
        "SR-Q-017": python_coverage._inspect,
        "SR-Q-018": python_coverage._inspect,
        "SR-Q-019": vulnerability_scanning._inspect,
        "SR-Q-020": dependabot_config._inspect,
        "SR-Q-021": helm_security_context._inspect,
        "SR-Q-022": helm_security_context._inspect,
        "SR-Q-023": helm_audit_retention._inspect,
        "SR-Q-024": api_server_security._inspect_api_server,
        "SR-Q-025": sbom_completeness._inspect,
        "SR-Q-026": slsa_verification._inspect,
        "SR-Q-027": github_actions_pinning._inspect,
        "SR-Q-028": network_policy_presence._inspect,
        "SR-Q-029": network_policy_presence._inspect,
        "SR-Q-030": api_server_security._inspect_api_server,
        "SR-Q-031": api_server_security._inspect_api_server,
        "SR-Q-032": api_server_security._inspect_api_server,
        "SR-Q-033": api_server_security._inspect_api_server,
        "SR-Q-034": api_server_security._inspect_api_server,
        "SR-Q-035": api_server_security._inspect_api_contracts,
        "SR-Q-036": api_server_security._inspect_api_server,
    }
    for sr_id, fn in _mapping.items():
        reg.register(sr_id, fn)
