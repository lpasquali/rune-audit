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
from rune_audit.sr2.inspectors.stdlib.tls_security import _inspect as inspect_tls


def test_inspect_api_server_not_found(tmp_path):
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-001", title="t", priority=Priority.P2)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.NOT_APPLICABLE
    assert "api_server.py not found" in res.detail


def test_inspect_api_server_sr_q_001(tmp_path):
    rune_dir = tmp_path / "rune_bench"
    rune_dir.mkdir(parents=True)
    api_server = rune_dir / "api_server.py"
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-001", title="t", priority=Priority.P2)
    
    # Fail
    api_server.write_text('nothing', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    api_server.write_text('len(secret) < 32', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_002(tmp_path):
    api_server = tmp_path / "rune_bench" / "api_server.py"
    api_server.parent.mkdir(parents=True, exist_ok=True)
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-002", title="t", priority=Priority.P2)
    
    # Fail
    api_server.write_text('nothing', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    api_server.write_text('Authorization: Bearer', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_003(tmp_path):
    api_server = tmp_path / "rune_bench" / "api_server.py"
    api_server.parent.mkdir(parents=True, exist_ok=True)
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-003", title="t", priority=Priority.P2)
    
    # Fail
    api_server.write_text('nothing', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    api_server.write_text('_SESSION_LIFETIME_SECONDS = 3600', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_004(tmp_path):
    api_server = tmp_path / "rune_bench" / "api_server.py"
    api_server.parent.mkdir(parents=True, exist_ok=True)
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-004", title="t", priority=Priority.P2)
    
    # Fail
    api_server.write_text('nothing', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    api_server.write_text('MAX_BODY_SIZE', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_005(tmp_path):
    api_server = tmp_path / "rune_bench" / "api_server.py"
    api_server.parent.mkdir(parents=True, exist_ok=True)
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-005", title="t", priority=Priority.P2)
    
    # Fail
    api_server.write_text('nothing', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    api_server.write_text('RateLimit', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_007_postgres(tmp_path):
    (tmp_path / "rune_bench").mkdir(parents=True, exist_ok=True)
    (tmp_path / "rune_bench" / "api_server.py").write_text("", encoding="utf-8")
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-007", title="t", priority=Priority.P2)
    
    # NA (missing postgres.py)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.NOT_APPLICABLE
    
    # Fail
    (tmp_path / "rune_bench" / "storage").mkdir(parents=True, exist_ok=True)
    pg = tmp_path / "rune_bench" / "storage" / "postgres.py"
    pg.write_text('nothing', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    pg.write_text('RUNE_PG_POOL_MAX', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_008(tmp_path):
    api_server = tmp_path / "rune_bench" / "api_server.py"
    api_server.parent.mkdir(parents=True, exist_ok=True)
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-008", title="t", priority=Priority.P2)
    
    # Fail
    api_server.write_text('nothing', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    api_server.write_text('TIMEOUT', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_010(tmp_path):
    (tmp_path / "rune_bench").mkdir(parents=True, exist_ok=True)
    (tmp_path / "rune_bench" / "api_server.py").write_text("", encoding="utf-8")
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-010", title="t", priority=Priority.P2)
    
    # NA (missing ollama.py)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.NOT_APPLICABLE
    
    # Fail
    (tmp_path / "rune_bench" / "backends").mkdir(parents=True, exist_ok=True)
    ollama = tmp_path / "rune_bench" / "backends" / "ollama.py"
    ollama.write_text("nothing", encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    ollama.write_text("timeout_seconds: int = 120", encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_012(tmp_path):
    (tmp_path / "rune_bench").mkdir(parents=True, exist_ok=True)
    (tmp_path / "rune_bench" / "api_server.py").write_text("", encoding="utf-8")
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-012", title="t", priority=Priority.P2)
    
    # NA (missing instance.py)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.NOT_APPLICABLE
    
    # Fail
    (tmp_path / "rune_bench" / "resources" / "vastai").mkdir(parents=True, exist_ok=True)
    vastai = tmp_path / "rune_bench" / "resources" / "vastai" / "instance.py"
    vastai.write_text("nothing", encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    vastai.write_text("timeout_seconds=300", encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_024(tmp_path):
    api_server = tmp_path / "rune_bench" / "api_server.py"
    api_server.parent.mkdir(parents=True, exist_ok=True)
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-024", title="t", priority=Priority.P2)
    
    # Fail
    api_server.write_text('nothing', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    api_server.write_text('class JsonFormatter', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_030(tmp_path):
    (tmp_path / "rune_bench").mkdir(parents=True, exist_ok=True)
    (tmp_path / "rune_bench" / "api_server.py").write_text("", encoding="utf-8")
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-030", title="t", priority=Priority.P2)
    
    # NA (missing costs.py)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.NOT_APPLICABLE
    
    # Fail
    (tmp_path / "rune_bench" / "common").mkdir(parents=True, exist_ok=True)
    costs = tmp_path / "rune_bench" / "common" / "costs.py"
    costs.write_text("nothing", encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    costs.write_text("confidence_score=0.8", encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_031(tmp_path):
    (tmp_path / "rune_bench").mkdir(parents=True, exist_ok=True)
    (tmp_path / "rune_bench" / "api_server.py").write_text("", encoding="utf-8")
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-031", title="t", priority=Priority.P2)
    
    # NA (missing costs.py)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.NOT_APPLICABLE
    
    # Fail
    (tmp_path / "rune_bench" / "common").mkdir(parents=True, exist_ok=True)
    costs = tmp_path / "rune_bench" / "common" / "costs.py"
    costs.write_text("nothing", encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    costs.write_text("cost > 20", encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_032(tmp_path):
    api_server = tmp_path / "rune_bench" / "api_server.py"
    api_server.parent.mkdir(parents=True, exist_ok=True)
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-032", title="t", priority=Priority.P2)
    
    # Fail
    api_server.write_text('nothing', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    api_server.write_text('_HEALTH_CHECK_TIMEOUT_S = 5.0', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_033(tmp_path):
    api_server = tmp_path / "rune_bench" / "api_server.py"
    api_server.parent.mkdir(parents=True, exist_ok=True)
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-033", title="t", priority=Priority.P2)
    
    # Fail
    api_server.write_text('nothing', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    api_server.write_text('_GRACEFUL_SHUTDOWN_TIMEOUT_S = 10.0', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_034(tmp_path):
    api_server = tmp_path / "rune_bench" / "api_server.py"
    api_server.parent.mkdir(parents=True, exist_ok=True)
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-034", title="t", priority=Priority.P2)
    
    # Fail
    api_server.write_text('nothing', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    api_server.write_text('import jsonschema', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_sr_q_036(tmp_path):
    api_server = tmp_path / "rune_bench" / "api_server.py"
    api_server.parent.mkdir(parents=True, exist_ok=True)
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-036", title="t", priority=Priority.P2)
    
    # Fail
    api_server.write_text('nothing', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    api_server.write_text('max_workers=10', encoding="utf-8")
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_api_server_unsupported(tmp_path):
    api_server = tmp_path / "rune_bench" / "api_server.py"
    api_server.parent.mkdir(parents=True, exist_ok=True)
    api_server.write_text('', encoding="utf-8")
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-999", title="t", priority=Priority.P2)
    res = _inspect_api_server(ctx, spec)
    assert res.status == InspectStatus.NOT_APPLICABLE


def test_inspect_api_contracts(tmp_path):
    contracts = tmp_path / "rune_bench" / "api_contracts.py"
    contracts.parent.mkdir(parents=True, exist_ok=True)
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-035", title="t", priority=Priority.P2)
    
    # Fail
    contracts.write_text("", encoding="utf-8")
    res = _inspect_api_contracts(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    contracts.write_text('def __post_init__(self) -> None: and _check_max_str', encoding="utf-8")
    res = _inspect_api_contracts(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_driver_timeouts(tmp_path):
    drivers = tmp_path / "rune_bench" / "drivers"
    drivers.mkdir(parents=True, exist_ok=True)
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-011", title="t", priority=Priority.P2)
    
    # Fail
    (drivers / "http.py").write_text("", encoding="utf-8")
    res = _inspect_driver_timeouts(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    (drivers / "http.py").write_text('driver_invocation_timeout_seconds()', encoding="utf-8")
    res = _inspect_driver_timeouts(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_helm_retention(tmp_path):
    values = tmp_path / "charts" / "rune" / "values.yaml"
    values.parent.mkdir(parents=True, exist_ok=True)
    
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-023", title="t", priority=Priority.P2)
    
    # Fail
    values.write_text("auditLogs:\n  retentionDays: 30\n", encoding="utf-8")
    res = inspect_helm_retention(ctx, spec)
    assert res.status == InspectStatus.FAIL
    
    # Pass
    values.write_text("auditLogs:\n  retentionDays: 90\n", encoding="utf-8")
    res = inspect_helm_retention(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_operator_success(tmp_path):
    controller = tmp_path / "controllers" / "runebenchmark_controller.go"
    controller.parent.mkdir(parents=True, exist_ok=True)
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
    # Note: stdlib.rbac_least_privilege is NOT mapped to SR-Q-033 in __init__.py, 
    # but the function itself should still work.
    assert res.status == InspectStatus.PASS


def test_inspect_tls_success(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text("min_version: tls1.2", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-015", title="t", priority=Priority.P2)
    res = inspect_tls(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_helm_security_context_sr_q_006(tmp_path):
    f = tmp_path / "charts" / "templates" / "deploy.yaml"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("workqueuedepth", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-006", title="t", priority=Priority.P2)
    from rune_audit.sr2.inspectors.stdlib.helm_security_context import _inspect as inspect_helm
    res = inspect_helm(ctx, spec)
    assert res.status == InspectStatus.PASS


def test_inspect_python_coverage_sr_q_018(tmp_path):
    (tmp_path / "pyproject.toml").write_text("hypothesis", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = RequirementSpec(id="SR-Q-018", title="t", priority=Priority.P2)
    from rune_audit.sr2.inspectors.stdlib.python_coverage import _inspect as inspect_pycov
    res = inspect_pycov(ctx, spec)
    assert res.status == InspectStatus.PASS
