# SPDX-License-Identifier: Apache-2.0
"""Integration-style runs on distinct repo layouts (rune-docs#230 evidence)."""

from __future__ import annotations

from pathlib import Path

import pytest

from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.models import InspectStatus, Priority, RequirementSpec
from rune_audit.sr2.registry import default_registry

RUNE_AUDIT_ROOT = Path(__file__).resolve().parents[1]


def _spec(rid: str) -> RequirementSpec:
    return RequirementSpec(id=rid, title="t", priority=Priority.P2)


@pytest.mark.integration
def test_profile_python_packaging_repo(tmp_path: Path) -> None:
    """Synthetic Python repo: coverage hints + license."""
    (tmp_path / "pyproject.toml").write_text("[tool.coverage]\nsource = ['src']\n", encoding="utf-8")
    (tmp_path / "LICENSE").write_text("Apache-2.0\n" + ("z" * 40), encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    reg = default_registry()
    assert reg.get("stdlib.python_coverage")(ctx, _spec("stdlib.python_coverage")).status == InspectStatus.PASS
    assert reg.get("stdlib.license_compliance")(ctx, _spec("stdlib.license_compliance")).status == InspectStatus.PASS
    assert reg.get("stdlib.go_coverage")(ctx, _spec("stdlib.go_coverage")).status == InspectStatus.NOT_APPLICABLE


@pytest.mark.integration
def test_profile_kubernetes_manifests_repo(tmp_path: Path) -> None:
    """Synthetic K8s repo: NetworkPolicy + Role."""
    manifests = tmp_path / "manifests"
    manifests.mkdir(parents=True)
    (manifests / "np.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny\n",
        encoding="utf-8",
    )
    (manifests / "role.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: app\n",
        encoding="utf-8",
    )
    ctx = InspectContext(root=tmp_path)
    reg = default_registry()
    assert reg.get("stdlib.network_policy_presence")(ctx, _spec("stdlib.network_policy_presence")).status == (
        InspectStatus.PASS
    )
    assert (
        reg.get("stdlib.rbac_least_privilege")(ctx, _spec("stdlib.rbac_least_privilege")).status == InspectStatus.PASS
    )


@pytest.mark.integration
def test_profile_rune_audit_checkout() -> None:
    """Real checkout: this repository should satisfy license + Python coverage heuristics."""
    ctx = InspectContext(root=RUNE_AUDIT_ROOT)
    reg = default_registry()
    lic = reg.get("stdlib.license_compliance")(ctx, _spec("stdlib.license_compliance"))
    cov = reg.get("stdlib.python_coverage")(ctx, _spec("stdlib.python_coverage"))
    assert lic.status == InspectStatus.PASS, lic.detail
    assert cov.status == InspectStatus.PASS, cov.detail
