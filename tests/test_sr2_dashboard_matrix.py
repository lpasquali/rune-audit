# SPDX-License-Identifier: Apache-2.0
"""SR-2 multi-repo dashboard (rune-docs#212)."""

from __future__ import annotations

import json
from pathlib import Path

from rune_audit.sr2.compliance_config import resolve_project_repo_paths
from rune_audit.sr2.dashboard_matrix import (
    build_matrix,
    collect_verify_reports,
    combined_summary,
    load_previous_dashboard,
    render_html,
    render_json_document,
    render_markdown,
    trend_delta,
)
from rune_audit.sr2.models import InspectResult, InspectStatus, VerifyReport


def test_resolve_project_repo_paths(tmp_path: Path) -> None:
    from rune_audit.sr2.compliance_config import ComplianceConfigFile, ProjectRepoEntry, ProjectSection

    cfg = ComplianceConfigFile(
        project=ProjectSection(
            name="t",
            github_org="o",
            repos=[ProjectRepoEntry(name="a"), ProjectRepoEntry(name="b")],
        ),
    )
    pairs = resolve_project_repo_paths(cfg, tmp_path)
    assert pairs[0] == ("a", (tmp_path / "a").resolve())


def test_build_matrix_and_summary() -> None:
    r1 = VerifyReport(
        results=[
            InspectResult(requirement_id="SR-Q-001", status=InspectStatus.PASS, detail=""),
            InspectResult(requirement_id="SR-Q-002", status=InspectStatus.FAIL, detail="x"),
        ],
        root="/a",
    )
    r2 = VerifyReport(
        results=[
            InspectResult(requirement_id="SR-Q-001", status=InspectStatus.NOT_IMPLEMENTED, detail=""),
        ],
        root="/b",
    )
    reports = {"repo-a": r1, "repo-b": r2}
    m = build_matrix(reports)
    assert m.cells[("SR-Q-001", "repo-a")] == "pass"
    assert m.cells[("SR-Q-002", "repo-a")] == "fail"
    assert m.cells[("SR-Q-001", "repo-b")] == "not_implemented"
    assert m.cells[("SR-Q-002", "repo-b")] == "not_implemented"
    summary = combined_summary(reports)
    assert "per_repo" in summary
    assert "total" in summary


def test_render_json_and_trend(tmp_path: Path) -> None:
    r = VerifyReport(
        results=[InspectResult(requirement_id="SR-Q-001", status=InspectStatus.PASS, detail="")],
        root="/x",
    )
    m = build_matrix({"only": r})
    summary = combined_summary({"only": r})
    doc = render_json_document(m, summary, {"pass": 1})
    assert doc["version"] == 1
    assert "matrix" in doc
    p = tmp_path / "dash.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    loaded = load_previous_dashboard(p)
    assert loaded is not None
    delta = trend_delta(summary, loaded)
    assert delta is not None


def test_render_markdown_contains_matrix() -> None:
    r = VerifyReport(
        results=[InspectResult(requirement_id="SR-Q-036", status=InspectStatus.NOT_APPLICABLE, detail="")],
        root="/z",
    )
    m = build_matrix({"z": r}, skipped_repos=["missing"])
    text = render_markdown(m, combined_summary({"z": r}))
    assert "SR-Q-036" in text
    assert "missing" in text


def test_render_html_escapes() -> None:
    r = VerifyReport(
        results=[InspectResult(requirement_id="SR-Q-001", status=InspectStatus.PASS, detail="<script>")],
        root="/z",
    )
    m = build_matrix({"repo": r})
    html = render_html(m, combined_summary({"repo": r}), None)
    assert "<script>" not in html or "&lt;script&gt;" in html
    assert "pass" in html


def test_collect_verify_reports_skips_missing(tmp_path: Path) -> None:
    existing = tmp_path / "exists"
    existing.mkdir()
    rep, skipped = collect_verify_reports([("exists", existing), ("gone", tmp_path / "nope")])
    assert "exists" in rep
    assert "gone" in skipped
