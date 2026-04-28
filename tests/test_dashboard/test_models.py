# SPDX-License-Identifier: Apache-2.0
"""Tests for dashboard models."""

from __future__ import annotations

from datetime import datetime

from rune_audit.dashboard.models import DashboardData, RepoAlerts, RepoCoverage, RepoStatus


class TestRepoStatus:
    def test_create(self):
        s = RepoStatus(repo="rune", workflow="quality-gates.yml", status="success")
        assert s.repo == "rune" and s.status == "success"

    def test_with_url(self):
        s = RepoStatus(repo="rune", workflow="qg", status="failure", run_url="https://example.com")
        assert s.run_url == "https://example.com"

    def test_with_timestamp(self):
        dt = datetime(2026, 4, 1, 12, 0, 0)
        s = RepoStatus(repo="rune", workflow="qg", status="success", updated_at=dt)
        assert s.updated_at == dt


class TestRepoCoverage:
    def test_create(self):
        c = RepoCoverage(repo="rune", coverage_pct=98.5)
        assert c.coverage_pct == 98.5 and c.floor == 97.0

    def test_defaults(self):
        c = RepoCoverage(repo="rune")
        assert c.language == "python" and c.coverage_pct == 0.0


class TestRepoAlerts:
    def test_create(self):
        a = RepoAlerts(repo="rune", dependabot_open=3, code_scanning_open=1, critical_cves=1)
        assert a.dependabot_open == 3 and a.critical_cves == 1

    def test_defaults(self):
        a = RepoAlerts(repo="rune")
        assert a.dependabot_open == 0


class TestDashboardData:
    def test_create_empty(self):
        d = DashboardData()
        assert d.repos == [] and d.coverage == [] and d.alerts == []

    def test_serialization(self):
        d = DashboardData(repos=[RepoStatus(repo="rune", workflow="qg", status="success")])
        j = d.model_dump_json()
        assert "rune" in j

    def test_full(self):
        d = DashboardData(
            repos=[RepoStatus(repo="rune", workflow="qg", status="success")],
            coverage=[RepoCoverage(repo="rune", coverage_pct=98.0)],
            alerts=[RepoAlerts(repo="rune", dependabot_open=2)],
        )
        assert len(d.repos) == 1 and len(d.coverage) == 1 and len(d.alerts) == 1
