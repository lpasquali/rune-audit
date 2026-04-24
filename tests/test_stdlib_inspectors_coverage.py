# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.models import InspectStatus, Priority, RequirementSpec
from rune_audit.sr2.inspectors.stdlib.api_server_security import (
    _inspect_api_server,
    _inspect_api_contracts,
    _inspect_driver_timeouts
)
from rune_audit.sr2.inspectors.stdlib.helm_audit_retention import _inspect as inspect_helm_retention
from rune_audit.sr2.inspectors.stdlib.operator_security import _inspect_operator
from rune_audit.sr2.inspectors.stdlib.rbac_least_privilege import _inspect as inspect_rbac
from rune_audit.sr2.inspectors.stdlib.network_policy_presence import _inspect as inspect_netpol


def test_inspect_api_server_not_found(tmp_path):
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-001", title="t", priority=Priority.P2)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.NOT_APPLICABLE
    assert "api_server.py not found" in res.detail


def test_inspect_api_server_success(tmp_path):
    rune_dir = tmp_path / "rune" / "rune_bench"
    rune_dir.mkdir(parents=True)
    api_server = rune_dir / "api_server.py"
    api_server.write_text('len(secret) < 32 and "minimum length is 32 characters"', encoding="utf-8")
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-001", title="t", priority=Priority.P2)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_001_fail(tmp_path):
    api_server = tmp_path / "rune_bench" / "api_server.py"
    api_server.parent.mkdir(parents=True)
    api_server.write_text('nothing', encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-001", title="t", priority=Priority.P2)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL


def test_inspect_api_server_sr_q_002_fail(tmp_path):
    api_server = tmp_path / "rune_bench" / "api_server.py"
    api_server.parent.mkdir(parents=True)
    api_server.write_text('nothing', encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-002", title="t", priority=Priority.P2)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL


def test_inspect_api_server_sr_q_007_postgres_fail(tmp_path):
    (tmp_path / "rune_bench").mkdir(parents=True)
    (tmp_path / "rune_bench" / "api_server.py").write_text("", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-007", title="t", priority=Priority.P2)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.NOT_APPLICABLE


def test_inspect_api_server_sr_q_007_postgres_low_pool(tmp_path):
    (tmp_path / "rune_bench" / "storage").mkdir(parents=True)
    (tmp_path / "rune_bench" / "api_server.py").write_text("", encoding="utf-8")
    pg = tmp_path / "rune_bench" / "storage" / "postgres.py"
    pg.write_text('NOTHING', encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-007", title="t", priority=Priority.P2)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL


def test_inspect_api_server_sr_q_004_fail(tmp_path):
    (tmp_path / "rune_bench").mkdir(parents=True)
    (tmp_path / "rune_bench" / "api_server.py").write_text("", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-004", title="t", priority=Priority.P2)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL


def test_inspect_api_server_sr_q_005_fail(tmp_path):
    (tmp_path / "rune_bench").mkdir(parents=True)
    (tmp_path / "rune_bench" / "api_server.py").write_text("", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-005", title="t", priority=Priority.P2)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL


def test_inspect_api_server_sr_q_008_fail(tmp_path):
    (tmp_path / "rune_bench").mkdir(parents=True)
    (tmp_path / "rune_bench" / "api_server.py").write_text("", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-008", title="t", priority=Priority.P2)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL


def test_inspect_api_server_sr_q_016_fail(tmp_path):
    (tmp_path / "rune_bench").mkdir(parents=True)
    (tmp_path / "rune_bench" / "api_server.py").write_text("", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-016", title="t", priority=Priority.P2)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL


def test_inspect_api_server_sr_q_024_fail(tmp_path):
    (tmp_path / "rune_bench").mkdir(parents=True)
    (tmp_path / "rune_bench" / "api_server.py").write_text("", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-024", title="t", priority=Priority.P2)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL


def test_inspect_api_contracts_fail(tmp_path):
    (tmp_path / "rune_bench").mkdir(parents=True)
    (tmp_path / "rune_bench" / "api_contracts.py").write_text("", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-035", title="t", priority=Priority.P2)
    res = _inspect_api_contracts(ctx, spec)
    assert res.status == InspectStatus.FAIL


def test_inspect_driver_timeouts_fail(tmp_path):
    (tmp_path / "rune_bench" / "drivers").mkdir(parents=True)
    (tmp_path / "rune_bench" / "drivers" / "http.py").write_text("", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-011", title="t", priority=Priority.P2)
    res = _inspect_driver_timeouts(ctx, spec)
    assert res.status == InspectStatus.FAIL


def test_inspect_helm_retention_not_set(tmp_path):
    values = tmp_path / "charts" / "rune" / "values.yaml"
    values.parent.mkdir(parents=True)
    values.write_text("auditLogs: {}\n", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-023", title="t", priority=Priority.P2)
    res = inspect_helm_retention(ctx, spec)
    assert res.status == InspectStatus.FAIL


def test_inspect_helm_retention_wrong_type(tmp_path):
    values = tmp_path / "charts" / "rune" / "values.yaml"
    values.parent.mkdir(parents=True)
    values.write_text("auditLogs:\n  retentionDays: '90'\n", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-023", title="t", priority=Priority.P2)
    res = inspect_helm_retention(ctx, spec)
    assert res.status == InspectStatus.FAIL


def test_inspect_helm_retention_low(tmp_path):
    values = tmp_path / "charts" / "rune" / "values.yaml"
    values.parent.mkdir(parents=True)
    values.write_text("auditLogs:\n  retentionDays: 30\n", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-023", title="t", priority=Priority.P2)
    res = inspect_helm_retention(ctx, spec)
    assert res.status == InspectStatus.FAIL


def test_inspect_operator_fail(tmp_path):
    controller = tmp_path / "controllers" / "runebenchmark_controller.go"
    controller.parent.mkdir(parents=True)
    controller.write_text('nothing', encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-009", title="t", priority=Priority.P2)
    res = _inspect_operator(ctx, spec)
    assert res.status == InspectStatus.FAIL


def test_inspect_operator_success(tmp_path):
    controller = tmp_path / "controllers" / "runebenchmark_controller.go"
    controller.parent.mkdir(parents=True)
    controller.write_text('TimeoutSeconds time.Duration', encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-009", title="t", priority=Priority.P2)
    res = _inspect_operator(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_rbac_success(tmp_path):
    role = tmp_path / "role.yaml"
    role.write_text("kind: Role\napiVersion: v1", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-033", title="t", priority=Priority.P2)
    res = inspect_rbac(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_netpol_success(tmp_path):
    np = tmp_path / "netpol.yaml"
    np.write_text("kind: NetworkPolicy\napiVersion: networking.k8s.io/v1", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-034", title="t", priority=Priority.P2)
    res = inspect_netpol(ctx, spec)
    assert res.status == InspectStatus.PASS
