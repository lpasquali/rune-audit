# SPDX-License-Identifier: Apache-2.0
from rune_audit.sr2.dashboard_matrix import (
    _status_css,
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


def test_status_css_unknown():
    assert _status_css("UNKNOWN_STATUS") == "unk"

def test_collect_verify_reports_skipped(tmp_path):
    repo_paths = [
        ("repo1", tmp_path / "repo1"),
        ("repo2", tmp_path / "repo2")
    ]
    (tmp_path / "repo1").mkdir()
    # repo2 does not exist
    reports, skipped = collect_verify_reports(repo_paths)
    assert "repo1" in reports
    assert "repo2" in skipped

def test_trend_delta_prev_none():
    assert trend_delta({"total": {}}, None) is None

def test_trend_delta_prev_invalid():
    # prev is dict but no 'total'
    assert trend_delta({"total": {"pass": 1}}, {"not_total": {}}) == {"pass": 1}
    # prev['total'] is not a dict
    assert trend_delta({"total": {"pass": 1}}, {"total": "NOT_A_DICT"}) is None

def test_render_markdown_with_skipped(tmp_path):
    reports = {"repo1": VerifyReport(results=[], root=str(tmp_path))}
    matrix = build_matrix(reports, skipped_repos=["repo2"])
    summary = combined_summary(reports)
    md = render_markdown(matrix, summary)
    assert "**Skipped (missing path):** `repo2`" in md

def test_render_html_with_trend(tmp_path):
    reports = {"repo1": VerifyReport(results=[], root=str(tmp_path))}
    matrix = build_matrix(reports, skipped_repos=["repo2"])
    summary = combined_summary(reports)
    trend = {"pass": 1, "fail": "STALE"}
    html = render_html(matrix, summary, trend)
    assert "Trend (vs previous)" in html
    assert "<code>pass</code>: +1" in html
    assert "<code>fail</code>: STALE" in html

def test_load_previous_dashboard_file_not_found(tmp_path):
    assert load_previous_dashboard(tmp_path / "missing.json") is None

def test_load_previous_dashboard_invalid_json(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("[1, 2, 3]", encoding="utf-8")
    assert load_previous_dashboard(f) is None

def test_render_json_document(tmp_path):
    reports = {"repo1": VerifyReport(results=[], root=str(tmp_path))}
    matrix = build_matrix(reports)
    summary = combined_summary(reports)
    doc = render_json_document(matrix, summary, None)
    assert doc["version"] == 1
    assert "repo1" in doc["repos"]

def test_priority_pass_rates_missing_id():
    from rune_audit.sr2.dashboard_matrix import priority_pass_rates
    report = VerifyReport(results=[
        InspectResult(requirement_id="UNKNOWN", status=InspectStatus.PASS, detail="")
    ], root=None)
    prio = priority_pass_rates(report)
    assert prio == {}
