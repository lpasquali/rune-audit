# SPDX-License-Identifier: Apache-2.0
"""Tests for dashboard collector with mocked GitHub API."""

from __future__ import annotations

import httpx
import respx

from rune_audit.dashboard.collector import DashboardCollector


class TestCollectWorkflowStatus:
    def test_success_run(self):
        with respx.mock(base_url="https://api.github.com") as mock:
            for repo in DashboardCollector.REPOS:
                mock.get(f"/repos/testowner/{repo}/actions/workflows/quality-gates.yml/runs").respond(
                    200,
                    json={
                        "workflow_runs": [
                            {
                                "conclusion": "success",
                                "html_url": f"https://example.com/{repo}/1",
                                "updated_at": "2026-04-01T12:00:00Z",
                            }
                        ]
                    },
                )
            client = httpx.Client(base_url="https://api.github.com")
            collector = DashboardCollector(owner="testowner", client=client)
            results = collector.collect_workflow_status()
        assert len(results) == 7
        assert results[0].status == "success"
        assert results[0].run_url != ""

    def test_no_runs(self):
        with respx.mock(base_url="https://api.github.com") as mock:
            for repo in DashboardCollector.REPOS:
                mock.get(f"/repos/testowner/{repo}/actions/workflows/quality-gates.yml/runs").respond(
                    200, json={"workflow_runs": []}
                )
            client = httpx.Client(base_url="https://api.github.com")
            results = DashboardCollector(owner="testowner", client=client).collect_workflow_status()
        assert all(r.status == "no_runs" for r in results)

    def test_api_error(self):
        with respx.mock(base_url="https://api.github.com") as mock:
            for repo in DashboardCollector.REPOS:
                mock.get(f"/repos/testowner/{repo}/actions/workflows/quality-gates.yml/runs").respond(404)
            client = httpx.Client(base_url="https://api.github.com")
            results = DashboardCollector(owner="testowner", client=client).collect_workflow_status()
        assert all(r.status == "unknown" for r in results)

    def test_http_error(self):
        with respx.mock(base_url="https://api.github.com") as mock:
            for repo in DashboardCollector.REPOS:
                mock.get(f"/repos/testowner/{repo}/actions/workflows/quality-gates.yml/runs").mock(
                    side_effect=httpx.ConnectError("fail")
                )
            client = httpx.Client(base_url="https://api.github.com")
            results = DashboardCollector(owner="testowner", client=client).collect_workflow_status()
        assert all(r.status == "error" for r in results)

    def test_no_updated_at(self):
        with respx.mock(base_url="https://api.github.com") as mock:
            for repo in DashboardCollector.REPOS:
                mock.get(f"/repos/testowner/{repo}/actions/workflows/quality-gates.yml/runs").respond(
                    200, json={"workflow_runs": [{"conclusion": "success", "html_url": "", "updated_at": None}]}
                )
            client = httpx.Client(base_url="https://api.github.com")
            results = DashboardCollector(owner="testowner", client=client).collect_workflow_status()
        assert results[0].updated_at is None


class TestCollectCoverage:
    def test_with_runs(self):
        with respx.mock(base_url="https://api.github.com") as mock:
            for repo in DashboardCollector.REPOS:
                mock.get(f"/repos/testowner/{repo}/actions/workflows/quality-gates.yml/runs").respond(
                    200, json={"workflow_runs": [{"id": 123}]}
                )
                mock.get(f"/repos/testowner/{repo}/actions/runs/123/jobs").respond(
                    200, json={"jobs": [{"steps": [{"name": "Run tests"}]}]}
                )
            client = httpx.Client(base_url="https://api.github.com")
            results = DashboardCollector(owner="testowner", client=client).collect_coverage()
        assert len(results) == 7

    def test_no_runs(self):
        with respx.mock(base_url="https://api.github.com") as mock:
            for repo in DashboardCollector.REPOS:
                mock.get(f"/repos/testowner/{repo}/actions/workflows/quality-gates.yml/runs").respond(
                    200, json={"workflow_runs": []}
                )
            client = httpx.Client(base_url="https://api.github.com")
            results = DashboardCollector(owner="testowner", client=client).collect_coverage()
        assert all(r.coverage_pct == 0.0 for r in results)

    def test_api_error(self):
        with respx.mock(base_url="https://api.github.com") as mock:
            for repo in DashboardCollector.REPOS:
                mock.get(f"/repos/testowner/{repo}/actions/workflows/quality-gates.yml/runs").respond(404)
            client = httpx.Client(base_url="https://api.github.com")
            results = DashboardCollector(owner="testowner", client=client).collect_coverage()
        assert len(results) == 7

    def test_jobs_api_error(self):
        with respx.mock(base_url="https://api.github.com") as mock:
            for repo in DashboardCollector.REPOS:
                mock.get(f"/repos/testowner/{repo}/actions/workflows/quality-gates.yml/runs").respond(
                    200, json={"workflow_runs": [{"id": 123}]}
                )
                mock.get(f"/repos/testowner/{repo}/actions/runs/123/jobs").respond(500)
            client = httpx.Client(base_url="https://api.github.com")
            results = DashboardCollector(owner="testowner", client=client).collect_coverage()
        assert len(results) == 7

    def test_http_error(self):
        with respx.mock(base_url="https://api.github.com") as mock:
            for repo in DashboardCollector.REPOS:
                mock.get(f"/repos/testowner/{repo}/actions/workflows/quality-gates.yml/runs").mock(
                    side_effect=httpx.ConnectError("fail")
                )
            client = httpx.Client(base_url="https://api.github.com")
            results = DashboardCollector(owner="testowner", client=client).collect_coverage()
        assert len(results) == 7


class TestCollectSecurityAlerts:
    def test_with_alerts(self):
        with respx.mock(base_url="https://api.github.com") as mock:
            for repo in DashboardCollector.REPOS:
                mock.get(f"/repos/testowner/{repo}/dependabot/alerts").respond(
                    200,
                    json=[
                        {"security_advisory": {"severity": "critical"}},
                        {"security_advisory": {"severity": "high"}},
                    ],
                )
                mock.get(f"/repos/testowner/{repo}/code-scanning/alerts").respond(
                    200,
                    json=[
                        {"rule": {"severity": "error"}},
                    ],
                )
            client = httpx.Client(base_url="https://api.github.com")
            results = DashboardCollector(owner="testowner", client=client).collect_security_alerts()
        assert len(results) == 7
        assert results[0].dependabot_open == 2
        assert results[0].critical_cves == 1
        assert results[0].code_scanning_open == 1

    def test_no_alerts(self):
        with respx.mock(base_url="https://api.github.com") as mock:
            for repo in DashboardCollector.REPOS:
                mock.get(f"/repos/testowner/{repo}/dependabot/alerts").respond(200, json=[])
                mock.get(f"/repos/testowner/{repo}/code-scanning/alerts").respond(200, json=[])
            client = httpx.Client(base_url="https://api.github.com")
            results = DashboardCollector(owner="testowner", client=client).collect_security_alerts()
        assert all(a.dependabot_open == 0 for a in results)

    def test_api_error(self):
        with respx.mock(base_url="https://api.github.com") as mock:
            for repo in DashboardCollector.REPOS:
                mock.get(f"/repos/testowner/{repo}/dependabot/alerts").respond(403)
                mock.get(f"/repos/testowner/{repo}/code-scanning/alerts").respond(403)
            client = httpx.Client(base_url="https://api.github.com")
            results = DashboardCollector(owner="testowner", client=client).collect_security_alerts()
        assert all(a.dependabot_open == 0 for a in results)

    def test_http_error(self):
        with respx.mock(base_url="https://api.github.com") as mock:
            for repo in DashboardCollector.REPOS:
                mock.get(f"/repos/testowner/{repo}/dependabot/alerts").mock(side_effect=httpx.ConnectError("fail"))
                mock.get(f"/repos/testowner/{repo}/code-scanning/alerts").mock(side_effect=httpx.ConnectError("fail"))
            client = httpx.Client(base_url="https://api.github.com")
            results = DashboardCollector(owner="testowner", client=client).collect_security_alerts()
        assert all(a.dependabot_open == 0 for a in results)


class TestCollectAll:
    def test_aggregates_all(self):
        with respx.mock(base_url="https://api.github.com") as mock:
            for repo in DashboardCollector.REPOS:
                mock.get(f"/repos/testowner/{repo}/actions/workflows/quality-gates.yml/runs").respond(
                    200,
                    json={
                        "workflow_runs": [
                            {"id": 1, "conclusion": "success", "html_url": "", "updated_at": "2026-04-01T12:00:00Z"}
                        ]
                    },
                )
                mock.get(f"/repos/testowner/{repo}/actions/runs/1/jobs").respond(200, json={"jobs": []})
                mock.get(f"/repos/testowner/{repo}/dependabot/alerts").respond(200, json=[])
                mock.get(f"/repos/testowner/{repo}/code-scanning/alerts").respond(200, json=[])
            client = httpx.Client(base_url="https://api.github.com")
            data = DashboardCollector(owner="testowner", client=client).collect_all()
        assert len(data.repos) == 7 and len(data.coverage) == 7 and len(data.alerts) == 7
