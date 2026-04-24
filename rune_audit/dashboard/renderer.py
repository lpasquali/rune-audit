# SPDX-License-Identifier: Apache-2.0
"""Dashboard rendering in terminal, markdown, and JSON formats."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rune_audit.dashboard.models import DashboardData


class DashboardRenderer:
    """Render dashboard data in multiple formats."""

    def render_terminal(self, data: DashboardData) -> str:
        """Rich-formatted terminal output."""
        lines: list[str] = []
        lines.append("RUNE Ecosystem Quality Dashboard")
        lines.append("=" * 50)
        lines.append(f"Collected: {data.collected_at}")
        lines.append("")

        lines.append("Workflow Status:")
        lines.append("-" * 40)
        for r in data.repos:
            icon = {"success": "[PASS]", "failure": "[FAIL]"}.get(r.status, "[????]")
            lines.append(f"  {icon} {r.repo:20s} {r.workflow}")

        lines.append("")
        lines.append("Coverage:")
        lines.append("-" * 40)
        for c in data.coverage:
            bar = "OK" if c.coverage_pct >= c.floor else "LOW"
            lines.append(f"  [{bar}] {c.repo:20s} {c.coverage_pct:5.1f}% (floor: {c.floor}%)")

        lines.append("")
        lines.append("Security Alerts:")
        lines.append("-" * 40)
        for a in data.alerts:
            a.dependabot_open + a.code_scanning_open
            lines.append(
                f"  {a.repo:20s} dependabot={a.dependabot_open} "
                f"code-scanning={a.code_scanning_open} critical={a.critical_cves}"
            )

        return "\n".join(lines)

    def render_markdown(self, data: DashboardData) -> str:
        """Markdown table for GitHub Pages/issues."""
        lines: list[str] = []
        lines.append("# RUNE Ecosystem Quality Dashboard")
        lines.append("")
        lines.append(f"Collected: {data.collected_at}")
        lines.append("")

        lines.append("## Workflow Status")
        lines.append("")
        lines.append("| Repository | Workflow | Status | Last Run |")
        lines.append("|---|---|---|---|")
        for r in data.repos:
            ts = str(r.updated_at) if r.updated_at else "N/A"
            lines.append(f"| {r.repo} | {r.workflow} | **{r.status}** | {ts} |")
        lines.append("")

        lines.append("## Coverage")
        lines.append("")
        lines.append("| Repository | Language | Coverage | Floor |")
        lines.append("|---|---|---|---|")
        for c in data.coverage:
            lines.append(f"| {c.repo} | {c.language} | {c.coverage_pct:.1f}% | {c.floor}% |")
        lines.append("")

        lines.append("## Security Alerts")
        lines.append("")
        lines.append("| Repository | Dependabot | Code Scanning | Critical |")
        lines.append("|---|---|---|---|")
        for a in data.alerts:
            lines.append(f"| {a.repo} | {a.dependabot_open} | {a.code_scanning_open} | {a.critical_cves} |")
        lines.append("")

        return "\n".join(lines)

    def render_json(self, data: DashboardData) -> str:
        """JSON for programmatic consumption."""
        return data.model_dump_json(indent=2)
