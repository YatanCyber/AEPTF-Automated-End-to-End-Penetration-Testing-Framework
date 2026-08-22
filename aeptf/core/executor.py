"""Shared execution engine used by the sync API, the async job queue, and
the CLI, so all three persist runs and findings identically."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from aeptf.core.config import Settings
from aeptf.core.plugins import PluginRegistry, PluginResult
from aeptf.core.safety import AuthorizationError
from aeptf.core.hooks import get_event_bus
from aeptf.database.models import Finding, Run


class UnknownPluginError(ValueError):
    pass


def execute_plugin(registry: PluginRegistry, settings: Settings, plugin_name: str, target: str) -> PluginResult:
    plugin = registry.get(plugin_name)
    if plugin is None:
        raise UnknownPluginError(f"Unknown plugin '{plugin_name}'. Available: {registry.names()}")
    return plugin.run(target, settings)  # AuthorizationError propagates to the caller


def _add_findings(session: Session, run: Run, result: PluginResult) -> None:
    for finding in result.findings:
        session.add(
            Finding(
                run_id=run.id,
                plugin=result.plugin_name,
                target=result.target,
                title=finding.title,
                severity=finding.severity,
                description=finding.description,
                evidence=finding.evidence,
            )
        )


def persist_result(
    session: Session,
    result: PluginResult,
    pipeline_id: str | None = None,
    pipeline_name: str | None = None,
) -> Run:
    """Create a brand-new Run row for a completed result. Use this for
    the synchronous request/response path, where no row exists yet."""
    run = Run(
        pipeline_id=pipeline_id,
        pipeline_name=pipeline_name,
        plugin=result.plugin_name,
        target=result.target,
        status=result.status,
        summary=result.summary,
        data=result.data,
        error=result.error,
        started_at=datetime.fromisoformat(result.started_at),
        finished_at=datetime.fromisoformat(result.finished_at),
    )
    session.add(run)
    session.flush()
    _add_findings(session, run, result)
    session.flush()
    session.refresh(run)
    return run


def update_run_with_result(session: Session, run: Run, result: PluginResult) -> Run:
    """Update an EXISTING Run row (e.g. the 'queued' placeholder an async
    job created) with a completed result, preserving its id so callers
    polling by that id keep working."""
    run.status = result.status
    run.summary = result.summary
    run.data = result.data
    run.error = result.error
    run.started_at = datetime.fromisoformat(result.started_at)
    run.finished_at = datetime.fromisoformat(result.finished_at)
    session.add(run)
    session.flush()
    _add_findings(session, run, result)
    session.flush()
    session.refresh(run)
    return run


def resolve_pipeline_steps(settings: Settings, pipeline_name: str | None) -> tuple[str, list[str]]:
    """Return (resolved_name, ordered plugin short-names) for a pipeline,
    falling back to settings.pipelines.default. Raises KeyError if the
    named pipeline doesn't exist."""
    name = pipeline_name or settings.pipelines.default
    if name not in settings.pipelines.definitions:
        raise KeyError(
            f"Unknown pipeline '{name}'. Available: {list(settings.pipelines.definitions)}"
        )
    return name, settings.pipelines.definitions[name]


def run_pipeline(
    session: Session,
    registry: PluginRegistry,
    settings: Settings,
    target: str,
    pipeline_name: str | None = None,
) -> tuple[str, str, list[Run]]:
    """Run every step of a named pipeline in order, persisting each step
    as it completes. Returns (pipeline_id, resolved_pipeline_name, runs).
    Stops and re-raises on the first AuthorizationError or unknown plugin."""
    resolved_name, steps = resolve_pipeline_steps(settings, pipeline_name)
    pipeline_id = str(uuid.uuid4())
    bus = get_event_bus()
    bus.emit("pipeline.started", {"pipeline_id": pipeline_id, "pipeline": resolved_name, "target": target})

    runs: list[Run] = []
    for plugin_name in steps:
        result = execute_plugin(registry, settings, plugin_name, target)
        runs.append(persist_result(session, result, pipeline_id=pipeline_id, pipeline_name=resolved_name))

    bus.emit("pipeline.finished", {"pipeline_id": pipeline_id, "pipeline": resolved_name, "target": target})
    return pipeline_id, resolved_name, runs
