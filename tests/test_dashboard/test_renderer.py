# SPDX-License-Identifier: Apache-2.0
"""Tests for dashboard renderer."""
from __future__ import annotations

import json
from datetime import datetime

from rune_audit.dashboard.models import DashboardData, RepoAlerts, RepoCoverage, RepoStatus
from rune_audit.dashboard.renderer import DashboardRenderer


def _make_data():
    return DashboardData(
        collected_at=datetime(2026, 4, 8, 6, 0, 0),
        repos=[
            RepoStatus(repo="rune", workflow="quality-gates.yml", status="success",
                       run_url="https://github.com/lpasquali/rune/actions/runs/1"),
            RepoStatus(repo="rune-operator", workflow="quality-gates.yml", status="failure"),
        ],
        coverage=[
            RepoCoverage(repo="rune", coverage_pct=98.5, floor=97.0),
            RepoCoverage(repo="rune-operator", coverage_pct=95.0, floor=97.0),
        ],
        alerts=[
            RepoAlerts(repo="rune", dependabot_open=2, code_scanning_open=1, critical_cves=0),
            RepoAlerts(repo="rune-operator", dependabot_open=0, code_scanning_open=0, critical_cves=0),
        ],
    )

class TestRenderTerminal:
    def test_contains_header(self):
        r = DashboardRenderer()
        output = r.render_terminal(_make_data())
        assert "RUNE Ecosystem Quality Dashboard" in output
    def test_contains_repos(self):
        output = DashboardRenderer().render_terminal(_make_data())
        assert "rune" in output and "rune-operator" in output
    def test_contains_pass_fail(self):
        output = DashboardRenderer().render_terminal(_make_data())
        assert "[PASS]" in output and "[FAIL]" in output
    def test_contains_coverage(self):
        output = DashboardRenderer().render_terminal(_make_data())
        assert "98.5%" in output
    def test_contains_alerts(self):
        output = DashboardRenderer().render_terminal(_make_data())
        assert "dependabot=2" in output

class TestRenderMarkdown:
    def test_contains_header(self):
        output = DashboardRenderer().render_markdown(_make_data())
        assert "# RUNE Ecosystem Quality Dashboard" in output
    def test_contains_tables(self):
        output = DashboardRenderer().render_markdown(_make_data())
        assert "| Repository |" in output
    def test_contains_status(self):
        output = DashboardRenderer().render_markdown(_make_data())
        assert "**success**" in output and "**failure**" in output
    def test_contains_coverage(self):
        output = DashboardRenderer().render_markdown(_make_data())
        assert "98.5%" in output
    def test_contains_alerts(self):
        output = DashboardRenderer().render_markdown(_make_data())
        assert "| rune | 2 |" in output

class TestRenderJson:
    def test_valid_json(self):
        output = DashboardRenderer().render_json(_make_data())
        data = json.loads(output)
        assert "collected_at" in data
    def test_repos_in_json(self):
        data = json.loads(DashboardRenderer().render_json(_make_data()))
        assert len(data["repos"]) == 2
    def test_coverage_in_json(self):
        data = json.loads(DashboardRenderer().render_json(_make_data()))
        assert data["coverage"][0]["coverage_pct"] == 98.5

class TestEmptyData:
    def test_terminal_empty(self):
        output = DashboardRenderer().render_terminal(DashboardData())
        assert "RUNE Ecosystem Quality Dashboard" in output
    def test_markdown_empty(self):
        output = DashboardRenderer().render_markdown(DashboardData())
        assert "# RUNE Ecosystem Quality Dashboard" in output
    def test_json_empty(self):
        data = json.loads(DashboardRenderer().render_json(DashboardData()))
        assert data["repos"] == []
