# SPDX-License-Identifier: Apache-2.0
"""SR-2 multi-repo compliance dashboard (rune-docs#212).

Produces matrix views: requirements (rows) × repositories (columns).
Output formats: HTML, JSON, Markdown. Optional trend vs a previous JSON artifact.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html import escape
from pathlib import Path  # noqa: TC003
from typing import Any

from rune_audit.sr2.catalog import iter_requirements
from rune_audit.sr2.engine import run_verification, summarize
from rune_audit.sr2.models import InspectStatus, Priority, VerifyReport

SCHEMA_URI = "https://github.com/lpasquali/rune-audit/blob/main/rune_audit/sr2/dashboard_matrix.py#schema-v1"

_STATUS_ORDER = (
    InspectStatus.PASS,
    InspectStatus.FAIL,
    InspectStatus.NOT_IMPLEMENTED,
    InspectStatus.NOT_APPLICABLE,
)


def _status_css(status: str) -> str:
    return {
        "pass": "pass",
        "fail": "fail",
        "not_implemented": "ni",
        "not_applicable": "na",
    }.get(status, "unk")


@dataclass
class DashboardMatrix:
    """Requirement id → repository → inspect status value."""

    repo_names: list[str]
    requirement_ids: list[str]
    cells: dict[tuple[str, str], str] = field(default_factory=dict)
    skipped_repos: list[str] = field(default_factory=list)


def collect_verify_reports(
    repo_paths: list[tuple[str, Path]],
    *,
    priority: Priority | None = None,
) -> tuple[dict[str, VerifyReport], list[str]]:
    """Run :func:`run_verification` per existing repo directory."""
    reports: dict[str, VerifyReport] = {}
    skipped: list[str] = []
    for name, root in repo_paths:
        if not root.is_dir():
            skipped.append(name)
            continue
        reports[name] = run_verification(root=root, priority=priority)
    return reports, skipped


def build_matrix(
    reports: dict[str, VerifyReport],
    *,
    skipped_repos: list[str] | None = None,
) -> DashboardMatrix:
    """Align rows to the SR-Q catalog order; columns follow *reports* key order."""
    req_ids = [s.id for s in iter_requirements()]
    repos = sorted(reports.keys())
    cells: dict[tuple[str, str], str] = {}
    for repo, rep in reports.items():
        by_id = {r.requirement_id: r.status.value for r in rep.results}
        for rid in req_ids:
            cells[(rid, repo)] = by_id.get(rid, "not_implemented")
    return DashboardMatrix(
        repo_names=repos,
        requirement_ids=req_ids,
        cells=cells,
        skipped_repos=list(skipped_repos or []),
    )


def priority_pass_rates(report: VerifyReport) -> dict[str, dict[str, int]]:
    """Per priority band: counts of each status."""
    spec_by_id = {s.id: s for s in iter_requirements()}
    buckets: dict[str, dict[str, int]] = {}
    for r in report.results:
        pr = spec_by_id.get(r.requirement_id)
        if pr is None:
            continue
        key = pr.priority.value
        buckets.setdefault(key, {s.value: 0 for s in _STATUS_ORDER})
        buckets[key][r.status.value] = buckets[key].get(r.status.value, 0) + 1
    return buckets


def combined_summary(reports: dict[str, VerifyReport]) -> dict[str, Any]:
    """Roll up :func:`summarize` per repo plus priority pass rates."""
    per_repo = {name: summarize(rep) for name, rep in reports.items()}
    prio: dict[str, dict[str, dict[str, int]]] = {}
    for name, rep in reports.items():
        prio[name] = priority_pass_rates(rep)
    total: dict[str, int] = {}
    for s in per_repo.values():
        for k, v in s.items():
            total[k] = total.get(k, 0) + v
    return {"per_repo": per_repo, "total": total, "priority_by_repo": prio}


def trend_delta(current: dict[str, Any], previous: dict[str, Any] | None) -> dict[str, Any] | None:
    """Compare ``summary.total``-style maps."""
    if previous is None:
        return None
    cur = current.get("total") or {}
    prev = previous.get("summary", {}).get("total")
    if not isinstance(prev, dict):
        prev = previous.get("total") or {}
    if not isinstance(prev, dict):
        return None
    keys = sorted(set(cur) | set(prev))
    return {k: (cur.get(k, 0) - int(prev.get(k, 0))) for k in keys}


def render_markdown(matrix: DashboardMatrix, summary: dict[str, Any]) -> str:
    lines = [
        "# SR-2 compliance dashboard",
        "",
        f"_Generated {datetime.now(tz=UTC).isoformat()}_",
        "",
    ]
    if matrix.skipped_repos:
        lines.append("**Skipped (missing path):** " + ", ".join(f"`{r}`" for r in matrix.skipped_repos))
        lines.append("")
    lines.append("## Summary (all repos)")
    total = summary.get("total") or {}
    lines.extend(f"- **{k}:** {v}" for k, v in sorted(total.items()))
    lines.append("")
    lines.append("## Matrix (requirement × repo)")
    lines.append("")
    header = "| Requirement | " + " | ".join(matrix.repo_names) + " |"
    sep = "| --- | " + " | ".join(["---"] * len(matrix.repo_names)) + " |"
    lines.extend([header, sep])
    for rid in matrix.requirement_ids:
        row = [rid]
        for repo in matrix.repo_names:
            row.append(matrix.cells.get((rid, repo), "—"))
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    return "\n".join(lines)


def render_html(matrix: DashboardMatrix, summary: dict[str, Any], trend: dict[str, Any] | None) -> str:
    """Self-contained HTML with minimal CSS (no external assets)."""
    total = summary.get("total") or {}
    css = """
    body { font-family: system-ui, sans-serif; margin: 1rem; background: #1e1e1e; color: #e0e0e0; }
    h1 { color: #7fdbff; }
    table { border-collapse: collapse; width: 100%; font-size: 0.85rem; }
    th, td { border: 1px solid #444; padding: 4px 6px; text-align: center; }
    th { background: #2a2a2a; position: sticky; top: 0; }
    td.req { text-align: left; font-family: monospace; }
    .pass { background: #1b4332; color: #b7e4c7; }
    .fail { background: #5c1010; color: #ffb3b3; }
    .ni { background: #5c4a10; color: #ffeaa7; }
    .na { background: #333; color: #aaa; }
    .unk { background: #333; }
    .summary { margin: 1rem 0; display: flex; gap: 1rem; flex-wrap: wrap; }
    .pill { padding: 0.25rem 0.6rem; border-radius: 4px; background: #2a2a2a; }
    """
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>SR-2 dashboard</title>",
        f"<style>{css}</style></head><body>",
        "<h1>SR-2 compliance dashboard</h1>",
        f"<p>Generated {escape(datetime.now(tz=UTC).isoformat())}</p>",
    ]
    if matrix.skipped_repos:
        parts.append("<p><strong>Skipped repos:</strong> " + escape(", ".join(matrix.skipped_repos)) + "</p>")
    parts.append("<div class='summary'>")
    for k, v in sorted(total.items()):
        parts.append(f"<span class='pill'><strong>{escape(k)}</strong>: {v}</span>")
    parts.append("</div>")
    if trend:
        parts.append("<h2>Trend (vs previous)</h2><ul>")
        for k, d in sorted(trend.items()):
            if isinstance(d, int):
                parts.append(f"<li><code>{escape(k)}</code>: {d:+d}</li>")
            else:
                parts.append(f"<li><code>{escape(k)}</code>: {escape(str(d))}</li>")
        parts.append("</ul>")
    parts.append("<h2>Matrix</h2><table><thead><tr><th>Requirement</th>")
    for repo in matrix.repo_names:
        parts.append(f"<th>{escape(repo)}</th>")
    parts.append("</tr></thead><tbody>")
    for rid in matrix.requirement_ids:
        parts.append("<tr><td class='req'>" + escape(rid) + "</td>")
        for repo in matrix.repo_names:
            st = matrix.cells.get((rid, repo), "not_implemented")
            cls = _status_css(st)
            parts.append(f"<td class='{cls}' title='{escape(st)}'>{escape(st)}</td>")
        parts.append("</tr>")
    parts.append("</tbody></table></body></html>")
    return "\n".join(parts)


def render_json_document(
    matrix: DashboardMatrix,
    summary: dict[str, Any],
    trend: dict[str, Any] | None,
) -> dict[str, Any]:
    """Machine-readable document; stable keys for CI."""
    mat: dict[str, dict[str, str]] = {rid: {} for rid in matrix.requirement_ids}
    for rid in matrix.requirement_ids:
        for repo in matrix.repo_names:
            mat[rid][repo] = matrix.cells.get((rid, repo), "not_implemented")
    return {
        "$schema": SCHEMA_URI,
        "version": 1,
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "repos": matrix.repo_names,
        "skipped_repos": matrix.skipped_repos,
        "requirements": matrix.requirement_ids,
        "matrix": mat,
        "summary": summary,
        "trend": trend,
    }


def load_previous_dashboard(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else None
