"""Markdown report generation for a single run or a pipeline of runs."""
from __future__ import annotations

from aeptf.database.models import Run


def _run_section(run: Run) -> str:
    lines = [
        f"## {run.plugin} — {run.target}",
        "",
        f"- **Run ID:** `{run.id}`",
        f"- **Status:** {run.status}",
        f"- **Started:** {run.started_at.isoformat() if run.started_at else 'n/a'}",
        f"- **Finished:** {run.finished_at.isoformat() if run.finished_at else 'n/a'}",
        "",
        f"**Summary:** {run.summary or 'n/a'}",
        "",
    ]
    if run.error:
        lines += [f"**Error:** {run.error}", ""]
    if run.findings:
        lines += ["### Findings", ""]
        for finding in run.findings:
            lines += [f"- **[{finding.severity.upper()}] {finding.title}** — {finding.description or ''}"]
        lines += [""]
    if run.data:
        lines += ["### Data", "", "```json", _pretty_json(run.data), "```", ""]
    return "\n".join(lines)


def _pretty_json(data: dict) -> str:
    import json

    return json.dumps(data, indent=2, default=str)


def render_run_report(run: Run) -> str:
    header = [
        "# AEPTF Run Report",
        "",
        f"Target: `{run.target}`  |  Plugin: `{run.plugin}`  |  Status: **{run.status}**",
        "",
        "---",
        "",
    ]
    return "\n".join(header) + _run_section(run)


def render_pipeline_report(pipeline_id: str, target: str, runs: list[Run]) -> str:
    header = [
        "# AEPTF Pipeline Report",
        "",
        f"Pipeline ID: `{pipeline_id}`",
        f"Target: `{target}`",
        f"Steps: {len(runs)}",
        "",
        "---",
        "",
    ]
    sections = [_run_section(run) for run in runs]
    return "\n".join(header) + "\n---\n\n".join(sections)
