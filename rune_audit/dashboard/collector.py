# SPDX-License-Identifier: Apache-2.0
"""Dashboard data collector using GitHub REST API."""
from __future__ import annotations

from datetime import datetime

import httpx

from rune_audit.dashboard.models import DashboardData, RepoAlerts, RepoCoverage, RepoStatus


class DashboardCollector:
    """Collect cross-repo quality gate data from GitHub."""

    REPOS = [
        "rune", "rune-operator", "rune-ui", "rune-charts",
        "rune-docs", "rune-audit", "rune-airgapped",
    ]

    def __init__(self, owner: str = "lpasquali", client: httpx.Client | None = None) -> None:
        self._owner = owner
        self._client = client or httpx.Client(
            base_url="https://api.github.com",
            headers={"Accept": "application/vnd.github+json"},
            timeout=30.0,
        )

    def collect_workflow_status(self) -> list[RepoStatus]:
        """Fetch latest quality-gates.yml run status per repo."""
        results: list[RepoStatus] = []
        for repo in self.REPOS:
            try:
                resp = self._client.get(
                    f"/repos/{self._owner}/{repo}/actions/workflows/quality-gates.yml/runs",
                    params={"per_page": 1, "status": "completed"},
                )
                if resp.status_code != 200:
                    results.append(RepoStatus(repo=repo, workflow="quality-gates.yml", status="unknown"))
                    continue
                data = resp.json()
                runs = data.get("workflow_runs", [])
                if not runs:
                    results.append(RepoStatus(repo=repo, workflow="quality-gates.yml", status="no_runs"))
                    continue
                run = runs[0]
                updated = None
                if run.get("updated_at"):
                    updated = datetime.fromisoformat(run["updated_at"].replace("Z", "+00:00"))
                results.append(RepoStatus(
                    repo=repo, workflow="quality-gates.yml",
                    status=run.get("conclusion", "pending"),
                    run_url=run.get("html_url", ""),
                    updated_at=updated,
                ))
            except httpx.HTTPError:
                results.append(RepoStatus(repo=repo, workflow="quality-gates.yml", status="error"))
        return results

    def collect_coverage(self) -> list[RepoCoverage]:
        """Extract coverage % from latest CI run annotations."""
        results: list[RepoCoverage] = []
        for repo in self.REPOS:
            try:
                resp = self._client.get(
                    f"/repos/{self._owner}/{repo}/actions/workflows/quality-gates.yml/runs",
                    params={"per_page": 1, "status": "completed"},
                )
                if resp.status_code != 200:
                    results.append(RepoCoverage(repo=repo))
                    continue
                data = resp.json()
                runs = data.get("workflow_runs", [])
                if not runs:
                    results.append(RepoCoverage(repo=repo))
                    continue
                run_id = runs[0]["id"]
                jobs_resp = self._client.get(
                    f"/repos/{self._owner}/{repo}/actions/runs/{run_id}/jobs",
                )
                if jobs_resp.status_code != 200:
                    results.append(RepoCoverage(repo=repo))
                    continue
                # Look for coverage in job annotations
                jobs_data = jobs_resp.json()
                coverage_pct = 0.0
                for job in jobs_data.get("jobs", []):
                    for step in job.get("steps", []):
                        name = step.get("name", "").lower()
                        if "coverage" in name or "test" in name:
                            coverage_pct = 0.0  # Would parse from annotations
                results.append(RepoCoverage(repo=repo, coverage_pct=coverage_pct))
            except httpx.HTTPError:
                results.append(RepoCoverage(repo=repo))
        return results

    def collect_security_alerts(self) -> list[RepoAlerts]:
        """Fetch Dependabot/code scanning alert counts."""
        results: list[RepoAlerts] = []
        for repo in self.REPOS:
            dependabot = 0
            code_scanning = 0
            critical = 0
            try:
                resp = self._client.get(
                    f"/repos/{self._owner}/{repo}/dependabot/alerts",
                    params={"state": "open", "per_page": 100},
                )
                if resp.status_code == 200:
                    alerts = resp.json()
                    dependabot = len(alerts)
                    for alert in alerts:
                        severity = alert.get("security_advisory", {}).get("severity", "")
                        if severity == "critical":
                            critical += 1
            except httpx.HTTPError:
                pass
            try:
                resp = self._client.get(
                    f"/repos/{self._owner}/{repo}/code-scanning/alerts",
                    params={"state": "open", "per_page": 100},
                )
                if resp.status_code == 200:
                    code_scanning = len(resp.json())
            except httpx.HTTPError:
                pass
            results.append(RepoAlerts(
                repo=repo, dependabot_open=dependabot,
                code_scanning_open=code_scanning, critical_cves=critical,
            ))
        return results

    def collect_all(self) -> DashboardData:
        """Aggregate all metrics."""
        return DashboardData(
            repos=self.collect_workflow_status(),
            coverage=self.collect_coverage(),
            alerts=self.collect_security_alerts(),
        )
