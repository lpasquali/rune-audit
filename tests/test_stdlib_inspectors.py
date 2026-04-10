# SPDX-License-Identifier: Apache-2.0
"""Standard inspector registry and heuristics (rune-docs#228, #230)."""

from __future__ import annotations

from pathlib import Path

import pytest

from rune_audit.sr2.engine import run_pack_verification
from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.models import InspectStatus, Priority, RequirementSpec
from rune_audit.sr2.registry import default_registry


@pytest.mark.parametrize(
    "stdlib_id",
    [
        "stdlib.python_coverage",
        "stdlib.go_coverage",
        "stdlib.helm_security_context",
        "stdlib.dockerfile_security",
        "stdlib.github_actions_pinning",
        "stdlib.dependabot_config",
        "stdlib.sbom_completeness",
        "stdlib.slsa_verification",
        "stdlib.secret_scanning",
        "stdlib.sast_coverage",
        "stdlib.license_compliance",
        "stdlib.vulnerability_scanning",
        "stdlib.container_signing",
        "stdlib.network_policy_presence",
        "stdlib.rbac_least_privilege",
    ],
)
def test_stdlib_ids_registered(stdlib_id: str) -> None:
    reg = default_registry()
    assert stdlib_id in set(reg.registered_ids())


def test_license_fail_without_file(tmp_path: Path) -> None:
    reg = default_registry()
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="stdlib.license_compliance", title="lic", priority=Priority.P2)
    r = reg.get("stdlib.license_compliance")(ctx, spec)
    assert r.status == InspectStatus.FAIL


def test_license_pass_with_license(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "LICENSE").write_text("Apache-2.0\n" + ("x" * 30), encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="stdlib.license_compliance", title="lic", priority=Priority.P2)
    r = reg.get("stdlib.license_compliance")(ctx, spec)
    assert r.status == InspectStatus.PASS


def test_run_pack_slsa_on_empty_repo(tmp_path: Path) -> None:
    report = run_pack_verification(root=tmp_path, pack_stem="slsa-l3")
    assert len(report.results) == 2
    assert {x.requirement_id for x in report.results} == {"SLSA-BUILD", "SLSA-SIGN"}
