# SPDX-License-Identifier: Apache-2.0
"""Standard inspector registry, heuristics, and mock-repo coverage (rune-docs#228, #230)."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from rune_audit.sr2.engine import run_pack_verification
from rune_audit.sr2.inspectors import InspectContext
from rune_audit.sr2.inspectors.stdlib import _util
from rune_audit.sr2.models import InspectStatus, Priority, RequirementSpec
from rune_audit.sr2.registry import default_registry


def _spec(rid: str, **extra: object) -> RequirementSpec:
    return RequirementSpec(id=rid, title="t", priority=Priority.P2, **extra)


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
    r = reg.get("stdlib.license_compliance")(ctx, _spec("stdlib.license_compliance"))
    assert r.status == InspectStatus.FAIL


def test_license_pass_with_license(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "LICENSE").write_text("Apache-2.0\n" + ("x" * 30), encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    r = reg.get("stdlib.license_compliance")(ctx, _spec("stdlib.license_compliance"))
    assert r.status == InspectStatus.PASS


def test_license_respects_min_license_bytes_threshold(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "LICENSE").write_text("short", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = _spec("stdlib.license_compliance", threshold={"min_license_bytes": 100})
    assert reg.get("stdlib.license_compliance")(ctx, spec).status == InspectStatus.FAIL


def test_license_invalid_threshold_falls_back(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "LICENSE").write_text("y" * 25, encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = _spec("stdlib.license_compliance", threshold={"min_license_bytes": True})
    assert reg.get("stdlib.license_compliance")(ctx, spec).status == InspectStatus.PASS


def test_license_min_bytes_clamped(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "LICENSE").write_text("x", encoding="utf-8")
    ctx = InspectContext(root=tmp_path)
    spec = _spec("stdlib.license_compliance", threshold={"min_license_bytes": 0})
    assert reg.get("stdlib.license_compliance")(ctx, spec).status == InspectStatus.PASS


def test_python_coverage_na_empty(tmp_path: Path) -> None:
    reg = default_registry()
    r = reg.get("stdlib.python_coverage")(InspectContext(root=tmp_path), _spec("stdlib.python_coverage"))
    assert r.status == InspectStatus.NOT_APPLICABLE


def test_python_coverage_pass_pyproject_coverage(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "pyproject.toml").write_text("[tool.coverage]\n", encoding="utf-8")
    r = reg.get("stdlib.python_coverage")(InspectContext(root=tmp_path), _spec("stdlib.python_coverage"))
    assert r.status == InspectStatus.PASS


def test_python_coverage_pass_coveragerc(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "pyproject.toml").write_text("[project]\nname=x\n", encoding="utf-8")
    (tmp_path / ".coveragerc").write_text("[run]\n", encoding="utf-8")
    r = reg.get("stdlib.python_coverage")(InspectContext(root=tmp_path), _spec("stdlib.python_coverage"))
    assert r.status == InspectStatus.PASS


def test_python_coverage_na_no_coverage_hints(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "pyproject.toml").write_text("[project]\nname=x\n", encoding="utf-8")
    r = reg.get("stdlib.python_coverage")(InspectContext(root=tmp_path), _spec("stdlib.python_coverage"))
    assert r.status == InspectStatus.NOT_APPLICABLE


def test_go_coverage_na_no_mod(tmp_path: Path) -> None:
    reg = default_registry()
    r = reg.get("stdlib.go_coverage")(InspectContext(root=tmp_path), _spec("stdlib.go_coverage"))
    assert r.status == InspectStatus.NOT_APPLICABLE


def test_go_coverage_pass(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    (tmp_path / "main_test.go").write_text("package x\n", encoding="utf-8")
    r = reg.get("stdlib.go_coverage")(InspectContext(root=tmp_path), _spec("stdlib.go_coverage"))
    assert r.status == InspectStatus.PASS


def test_go_coverage_na_no_tests(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    r = reg.get("stdlib.go_coverage")(InspectContext(root=tmp_path), _spec("stdlib.go_coverage"))
    assert r.status == InspectStatus.NOT_APPLICABLE


def test_helm_security_context_pass(tmp_path: Path) -> None:
    reg = default_registry()
    p = tmp_path / "charts" / "app" / "templates" / "dep.yaml"
    p.parent.mkdir(parents=True)
    p.write_text("securityContext:\n  runAsNonRoot: true\n", encoding="utf-8")
    r = reg.get("stdlib.helm_security_context")(InspectContext(root=tmp_path), _spec("stdlib.helm_security_context"))
    assert r.status == InspectStatus.PASS


def test_helm_security_context_pass_yml(tmp_path: Path) -> None:
    reg = default_registry()
    p = tmp_path / "charts" / "app" / "templates" / "dep.yml"
    p.parent.mkdir(parents=True)
    p.write_text("podSecurityContext:\n  fsGroup: 1000\n", encoding="utf-8")
    r = reg.get("stdlib.helm_security_context")(InspectContext(root=tmp_path), _spec("stdlib.helm_security_context"))
    assert r.status == InspectStatus.PASS


def test_helm_security_context_na(tmp_path: Path) -> None:
    reg = default_registry()
    r = reg.get("stdlib.helm_security_context")(InspectContext(root=tmp_path), _spec("stdlib.helm_security_context"))
    assert r.status == InspectStatus.NOT_APPLICABLE


def test_dockerfile_security_flows(tmp_path: Path) -> None:
    reg = default_registry()
    r = reg.get("stdlib.dockerfile_security")(InspectContext(root=tmp_path), _spec("stdlib.dockerfile_security"))
    assert r.status == InspectStatus.NOT_APPLICABLE

    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    r = reg.get("stdlib.dockerfile_security")(InspectContext(root=tmp_path), _spec("stdlib.dockerfile_security"))
    assert r.status == InspectStatus.FAIL

    (tmp_path / "Dockerfile").write_text("FROM alpine\nUSER 65534\n", encoding="utf-8")
    r = reg.get("stdlib.dockerfile_security")(InspectContext(root=tmp_path), _spec("stdlib.dockerfile_security"))
    assert r.status == InspectStatus.PASS


def test_github_actions_pinning(tmp_path: Path) -> None:
    reg = default_registry()
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    r = reg.get("stdlib.github_actions_pinning")(InspectContext(root=tmp_path), _spec("stdlib.github_actions_pinning"))
    assert r.status == InspectStatus.NOT_APPLICABLE

    (wf / "ci.yaml").write_text("on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n", encoding="utf-8")
    r = reg.get("stdlib.github_actions_pinning")(InspectContext(root=tmp_path), _spec("stdlib.github_actions_pinning"))
    assert r.status == InspectStatus.NOT_APPLICABLE

    (wf / "ci.yaml").write_text(
        "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@main\n",
        encoding="utf-8",
    )
    r = reg.get("stdlib.github_actions_pinning")(InspectContext(root=tmp_path), _spec("stdlib.github_actions_pinning"))
    assert r.status == InspectStatus.FAIL

    (wf / "ci.yaml").write_text(
        "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    r = reg.get("stdlib.github_actions_pinning")(InspectContext(root=tmp_path), _spec("stdlib.github_actions_pinning"))
    assert r.status == InspectStatus.PASS

    sha = "a" * 40
    (wf / "pin.yaml").write_text(
        f"on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{sha}\n",
        encoding="utf-8",
    )
    r = reg.get("stdlib.github_actions_pinning")(InspectContext(root=tmp_path), _spec("stdlib.github_actions_pinning"))
    assert r.status == InspectStatus.PASS

    for p in list(wf.glob("*.yml")) + list(wf.glob("*.yaml")):
        p.unlink()
    (wf / "skip.yaml").write_text(
        "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker://alpine:3\n"
        "      - uses: actions/checkout@${{ github.sha }}\n",
        encoding="utf-8",
    )
    r = reg.get("stdlib.github_actions_pinning")(InspectContext(root=tmp_path), _spec("stdlib.github_actions_pinning"))
    assert r.status == InspectStatus.PASS


def test_dependabot_config(tmp_path: Path) -> None:
    reg = default_registry()
    r = reg.get("stdlib.dependabot_config")(InspectContext(root=tmp_path), _spec("stdlib.dependabot_config"))
    assert r.status == InspectStatus.NOT_APPLICABLE
    d = tmp_path / ".github"
    d.mkdir(parents=True)
    (d / "dependabot.yml").write_text("version: 2\n", encoding="utf-8")
    r = reg.get("stdlib.dependabot_config")(InspectContext(root=tmp_path), _spec("stdlib.dependabot_config"))
    assert r.status == InspectStatus.PASS


def test_sbom_completeness(tmp_path: Path) -> None:
    reg = default_registry()
    r = reg.get("stdlib.sbom_completeness")(InspectContext(root=tmp_path), _spec("stdlib.sbom_completeness"))
    assert r.status == InspectStatus.NOT_APPLICABLE
    (tmp_path / "sbom.json").write_text("{}", encoding="utf-8")
    r = reg.get("stdlib.sbom_completeness")(InspectContext(root=tmp_path), _spec("stdlib.sbom_completeness"))
    assert r.status == InspectStatus.PASS


def test_slsa_secret_sast_vuln_container_workflows(tmp_path: Path) -> None:
    reg = default_registry()
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)

    for stdlib_id, text, expect in (
        ("stdlib.slsa_verification", "slsa-build-generator\n", InspectStatus.PASS),
        ("stdlib.secret_scanning", "secret scanning enabled\n", InspectStatus.PASS),
        ("stdlib.sast_coverage", "codeql\n", InspectStatus.PASS),
        ("stdlib.vulnerability_scanning", "grype\n", InspectStatus.PASS),
        ("stdlib.container_signing", "cosign sign\n", InspectStatus.PASS),
    ):
        (wf / "x.yml").write_text(text, encoding="utf-8")
        r = reg.get(stdlib_id)(InspectContext(root=tmp_path), _spec(stdlib_id))
        assert r.status == expect, stdlib_id

    for p in list(wf.glob("*.yml")) + list(wf.glob("*.yaml")):
        p.unlink()
    (wf / "noop.yml").write_text("name: noop\n", encoding="utf-8")
    for stdlib_id in (
        "stdlib.slsa_verification",
        "stdlib.secret_scanning",
        "stdlib.sast_coverage",
        "stdlib.vulnerability_scanning",
        "stdlib.container_signing",
    ):
        r = reg.get(stdlib_id)(InspectContext(root=tmp_path), _spec(stdlib_id))
        assert r.status == InspectStatus.NOT_APPLICABLE


def test_network_policy_and_rbac(tmp_path: Path) -> None:
    reg = default_registry()
    r = reg.get("stdlib.network_policy_presence")(
        InspectContext(root=tmp_path), _spec("stdlib.network_policy_presence")
    )
    assert r.status == InspectStatus.NOT_APPLICABLE
    (tmp_path / "np.yaml").write_text("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n", encoding="utf-8")
    r = reg.get("stdlib.network_policy_presence")(
        InspectContext(root=tmp_path), _spec("stdlib.network_policy_presence")
    )
    assert r.status == InspectStatus.PASS
    (tmp_path / "np.yaml").unlink()
    (tmp_path / "np.yml").write_text("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n", encoding="utf-8")
    r = reg.get("stdlib.network_policy_presence")(
        InspectContext(root=tmp_path), _spec("stdlib.network_policy_presence")
    )
    assert r.status == InspectStatus.PASS

    r = reg.get("stdlib.rbac_least_privilege")(InspectContext(root=tmp_path), _spec("stdlib.rbac_least_privilege"))
    assert r.status == InspectStatus.NOT_APPLICABLE
    (tmp_path / "role.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: x\n",
        encoding="utf-8",
    )
    r = reg.get("stdlib.rbac_least_privilege")(InspectContext(root=tmp_path), _spec("stdlib.rbac_least_privilege"))
    assert r.status == InspectStatus.PASS


def test_read_text_safe_oserror(tmp_path: Path) -> None:
    p = tmp_path / "w.yml"
    p.write_text("x", encoding="utf-8")
    with patch.object(Path, "read_text", side_effect=OSError("denied")):
        assert _util.read_text_safe(p) == ""


def test_threshold_int_variants() -> None:
    s = _spec("x", threshold={"n": 7})
    assert _util.threshold_int(s, "n", 3) == 7
    assert _util.threshold_int(s, "missing", 3) == 3
    assert _util.threshold_int(_spec("x"), "n", 3) == 3
    assert _util.threshold_int(_spec("x", threshold={"n": "12"}), "n", 3) == 12
    assert _util.threshold_int(_spec("x", threshold={"n": True}), "n", 3) == 3
    assert _util.threshold_int(_spec("x", threshold={"n": object()}), "n", 3) == 3


def test_run_pack_slsa_on_empty_repo(tmp_path: Path) -> None:
    report = run_pack_verification(root=tmp_path, pack_stem="slsa-l3")
    assert len(report.results) == 2
    assert {x.requirement_id for x in report.results} == {"SLSA-BUILD", "SLSA-SIGN"}


@pytest.mark.parametrize(
    ("stdlib_id", "needle"),
    [
        ("stdlib.github_actions_pinning", "no .github/workflows"),
        ("stdlib.slsa_verification", "no workflows"),
        ("stdlib.secret_scanning", "no workflows"),
        ("stdlib.sast_coverage", "no workflows"),
        ("stdlib.vulnerability_scanning", "no workflows"),
        ("stdlib.container_signing", "no workflows"),
    ],
)
def test_workflow_inspectors_na_without_dot_github(tmp_path: Path, stdlib_id: str, needle: str) -> None:
    reg = default_registry()
    r = reg.get(stdlib_id)(InspectContext(root=tmp_path), _spec(stdlib_id))
    assert r.status == InspectStatus.NOT_APPLICABLE
    assert needle in r.detail


def test_python_coverage_setup_py_only_no_coverage_hints(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "setup.py").write_text('print("x")\n', encoding="utf-8")
    r = reg.get("stdlib.python_coverage")(InspectContext(root=tmp_path), _spec("stdlib.python_coverage"))
    assert r.status == InspectStatus.NOT_APPLICABLE
    assert "no coverage" in r.detail


def test_python_coverage_unreadable_pyproject(tmp_path: Path) -> None:
    reg = default_registry()
    p = tmp_path / "pyproject.toml"
    p.write_text("[project]\nname=x\n", encoding="utf-8")
    p.chmod(0)
    try:
        r = reg.get("stdlib.python_coverage")(InspectContext(root=tmp_path), _spec("stdlib.python_coverage"))
    finally:
        p.chmod(0o644)
    assert r.status == InspectStatus.NOT_APPLICABLE


def test_license_negative_threshold_clamped(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "LICENSE").write_text("x", encoding="utf-8")
    spec = _spec("stdlib.license_compliance", threshold={"min_license_bytes": -9})
    r = reg.get("stdlib.license_compliance")(InspectContext(root=tmp_path), spec)
    assert r.status == InspectStatus.PASS


def test_dockerfile_skips_unreadable_then_reads_nested(tmp_path: Path) -> None:
    reg = default_registry()
    root_df = tmp_path / "Dockerfile"
    root_df.write_text("FROM scratch\n", encoding="utf-8")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "Dockerfile").write_text("FROM alpine\nUSER 65534\n", encoding="utf-8")
    root_df.chmod(0)
    try:
        r = reg.get("stdlib.dockerfile_security")(InspectContext(root=tmp_path), _spec("stdlib.dockerfile_security"))
    finally:
        root_df.chmod(0o644)
    assert r.status == InspectStatus.PASS


def test_dockerfile_max_scan_threshold_zero_clamps(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    spec = _spec("stdlib.dockerfile_security", threshold={"max_dockerfiles_to_scan": 0})
    r = reg.get("stdlib.dockerfile_security")(InspectContext(root=tmp_path), spec)
    assert r.status == InspectStatus.FAIL


def test_helm_skips_unscoped_yaml(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "root.yaml").write_text("a: 1\n", encoding="utf-8")
    r = reg.get("stdlib.helm_security_context")(InspectContext(root=tmp_path), _spec("stdlib.helm_security_context"))
    assert r.status == InspectStatus.NOT_APPLICABLE


def test_helm_yaml_oserror_then_good_file(tmp_path: Path) -> None:
    reg = default_registry()
    c = tmp_path / "charts" / "x" / "templates"
    c.mkdir(parents=True)
    bad = c / "locked.yaml"
    good = c / "ok.yaml"
    bad.write_text("x: 1\n", encoding="utf-8")
    good.write_text("securityContext:\n  runAsNonRoot: true\n", encoding="utf-8")
    bad.chmod(0)
    try:
        r = reg.get("stdlib.helm_security_context")(
            InspectContext(root=tmp_path), _spec("stdlib.helm_security_context")
        )
    finally:
        bad.chmod(0o644)
    assert r.status == InspectStatus.PASS


def test_helm_yml_oserror_then_good_file(tmp_path: Path) -> None:
    reg = default_registry()
    c = tmp_path / "charts" / "y" / "templates"
    c.mkdir(parents=True)
    bad = c / "locked.yml"
    good = c / "ok.yml"
    bad.write_text("x: 1\n", encoding="utf-8")
    good.write_text("securityContext:\n  runAsNonRoot: true\n", encoding="utf-8")
    bad.chmod(0)
    try:
        r = reg.get("stdlib.helm_security_context")(
            InspectContext(root=tmp_path), _spec("stdlib.helm_security_context")
        )
    finally:
        bad.chmod(0o644)
    assert r.status == InspectStatus.PASS


def test_helm_second_chart_file_has_security_context(tmp_path: Path) -> None:
    reg = default_registry()
    c = tmp_path / "charts" / "z" / "templates"
    c.mkdir(parents=True)
    (c / "plain.yaml").write_text("replicaCount: 1\n", encoding="utf-8")
    (c / "pod.yaml").write_text("securityContext:\n  runAsNonRoot: true\n", encoding="utf-8")
    r = reg.get("stdlib.helm_security_context")(InspectContext(root=tmp_path), _spec("stdlib.helm_security_context"))
    assert r.status == InspectStatus.PASS


def test_network_policy_skips_large_yaml_then_matches_yml(tmp_path: Path) -> None:
    reg = default_registry()
    huge = tmp_path / "big.yaml"
    huge.write_bytes(b"x: 1\n" + b"#" * 500_000)
    assert huge.stat().st_size > 500_000
    (tmp_path / "np.yml").write_text("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n", encoding="utf-8")
    r = reg.get("stdlib.network_policy_presence")(
        InspectContext(root=tmp_path), _spec("stdlib.network_policy_presence")
    )
    assert r.status == InspectStatus.PASS


def test_network_policy_skips_broken_symlink(tmp_path: Path) -> None:
    reg = default_registry()
    link = tmp_path / "broken.yaml"
    link.symlink_to(tmp_path / "missing-network-policy-target")
    (tmp_path / "np.yaml").write_text("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n", encoding="utf-8")
    r = reg.get("stdlib.network_policy_presence")(
        InspectContext(root=tmp_path), _spec("stdlib.network_policy_presence")
    )
    assert r.status == InspectStatus.PASS


def test_rbac_skips_large_manifest(tmp_path: Path) -> None:
    reg = default_registry()
    big = tmp_path / "big.yaml"
    big.write_bytes(b"kind: X\n" + b"#" * 500_000)
    assert big.stat().st_size > 500_000
    (tmp_path / "role.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: x\n",
        encoding="utf-8",
    )
    r = reg.get("stdlib.rbac_least_privilege")(InspectContext(root=tmp_path), _spec("stdlib.rbac_least_privilege"))
    assert r.status == InspectStatus.PASS


def test_rbac_skips_broken_symlink(tmp_path: Path) -> None:
    reg = default_registry()
    link = tmp_path / "gone.yaml"
    link.symlink_to(tmp_path / "nope")
    (tmp_path / "role.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: x\n",
        encoding="utf-8",
    )
    r = reg.get("stdlib.rbac_least_privilege")(InspectContext(root=tmp_path), _spec("stdlib.rbac_least_privilege"))
    assert r.status == InspectStatus.PASS


def test_rbac_skips_manifest_without_kind(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "plain.yaml").write_text("foo: bar\n", encoding="utf-8")
    (tmp_path / "role.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: x\n",
        encoding="utf-8",
    )
    r = reg.get("stdlib.rbac_least_privilege")(InspectContext(root=tmp_path), _spec("stdlib.rbac_least_privilege"))
    assert r.status == InspectStatus.PASS


def test_helm_skips_yml_outside_chart_paths(tmp_path: Path) -> None:
    """`.yml` at repo root is ignored (line 26–27 filter) even if it mentions securityContext."""
    reg = default_registry()
    (tmp_path / "loose.yml").write_text("securityContext:\n  runAsNonRoot: true\n", encoding="utf-8")
    r = reg.get("stdlib.helm_security_context")(InspectContext(root=tmp_path), _spec("stdlib.helm_security_context"))
    assert r.status == InspectStatus.NOT_APPLICABLE


def test_helm_match_from_yml_loop_only(tmp_path: Path) -> None:
    """No chart `*.yaml` hits; first `.yml` under templates carries securityContext."""
    reg = default_registry()
    c = tmp_path / "charts" / "solo" / "templates"
    c.mkdir(parents=True)
    (c / "values.yml").write_text("podSecurityContext:\n  fsGroup: 1\n", encoding="utf-8")
    r = reg.get("stdlib.helm_security_context")(InspectContext(root=tmp_path), _spec("stdlib.helm_security_context"))
    assert r.status == InspectStatus.PASS


def test_helm_read_text_oserror_on_only_chart_yaml(tmp_path: Path) -> None:
    """`rglob` order is filesystem-defined; a sole chart YAML that raises OSError hits except/continue."""
    reg = default_registry()
    c = tmp_path / "charts" / "m" / "templates"
    c.mkdir(parents=True)
    (c / "solo.yaml").write_text("x: 1\n", encoding="utf-8")
    orig = Path.read_text

    def _read(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == "solo.yaml":
            raise OSError("mock read failure")
        return orig(self, *args, **kwargs)

    with patch.object(Path, "read_text", _read):
        r = reg.get("stdlib.helm_security_context")(
            InspectContext(root=tmp_path), _spec("stdlib.helm_security_context")
        )
    assert r.status == InspectStatus.NOT_APPLICABLE


def test_helm_read_text_oserror_then_ok_ordered_names(tmp_path: Path) -> None:
    """Prefix files so the failing path sorts before the good one regardless of `rglob` order."""
    reg = default_registry()
    c = tmp_path / "charts" / "m2" / "templates"
    c.mkdir(parents=True)
    (c / "0_fail.yaml").write_text("x: 1\n", encoding="utf-8")
    (c / "1_ok.yaml").write_text("securityContext:\n  runAsNonRoot: true\n", encoding="utf-8")
    orig = Path.read_text

    def _read(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == "0_fail.yaml":
            raise OSError("mock read failure")
        return orig(self, *args, **kwargs)

    with patch.object(Path, "read_text", _read):
        r = reg.get("stdlib.helm_security_context")(
            InspectContext(root=tmp_path), _spec("stdlib.helm_security_context")
        )
    assert r.status == InspectStatus.PASS


def test_helm_read_text_oserror_on_only_chart_yml(tmp_path: Path) -> None:
    reg = default_registry()
    c = tmp_path / "charts" / "n" / "templates"
    c.mkdir(parents=True)
    (c / "solo.yml").write_text("x: 1\n", encoding="utf-8")
    orig = Path.read_text

    def _read(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == "solo.yml":
            raise OSError("mock read failure")
        return orig(self, *args, **kwargs)

    with patch.object(Path, "read_text", _read):
        r = reg.get("stdlib.helm_security_context")(
            InspectContext(root=tmp_path), _spec("stdlib.helm_security_context")
        )
    assert r.status == InspectStatus.NOT_APPLICABLE


def test_helm_read_text_oserror_then_ok_ordered_yml(tmp_path: Path) -> None:
    reg = default_registry()
    c = tmp_path / "charts" / "n2" / "templates"
    c.mkdir(parents=True)
    (c / "0_fail.yml").write_text("x: 1\n", encoding="utf-8")
    (c / "1_ok.yml").write_text("securityContext:\n  runAsNonRoot: true\n", encoding="utf-8")
    orig = Path.read_text

    def _read(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == "0_fail.yml":
            raise OSError("mock read failure")
        return orig(self, *args, **kwargs)

    with patch.object(Path, "read_text", _read):
        r = reg.get("stdlib.helm_security_context")(
            InspectContext(root=tmp_path), _spec("stdlib.helm_security_context")
        )
    assert r.status == InspectStatus.PASS


def test_network_policy_yaml_without_match_then_netpol(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "pod.yaml").write_text("kind: Pod\nmetadata:\n  name: x\n", encoding="utf-8")
    (tmp_path / "netpol.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default\n",
        encoding="utf-8",
    )
    r = reg.get("stdlib.network_policy_presence")(
        InspectContext(root=tmp_path), _spec("stdlib.network_policy_presence")
    )
    assert r.status == InspectStatus.PASS


def test_network_policy_match_in_yml_only(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "pol.yml").write_text("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n", encoding="utf-8")
    r = reg.get("stdlib.network_policy_presence")(
        InspectContext(root=tmp_path), _spec("stdlib.network_policy_presence")
    )
    assert r.status == InspectStatus.PASS


def test_network_policy_stat_oserror_skipped(tmp_path: Path) -> None:
    reg = default_registry()
    (tmp_path / "weird.yaml").write_text("kind: NetworkPolicy\n", encoding="utf-8")
    (tmp_path / "ok.yaml").write_text("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n", encoding="utf-8")
    orig_stat = Path.stat

    def _stat(self: Path, *args: object, **kwargs: object) -> os.stat_result:
        if self.name == "weird.yaml":
            raise OSError("mock stat failure")
        return orig_stat(self, *args, **kwargs)

    with patch.object(Path, "stat", _stat):
        r = reg.get("stdlib.network_policy_presence")(
            InspectContext(root=tmp_path), _spec("stdlib.network_policy_presence")
        )
    assert r.status == InspectStatus.PASS
