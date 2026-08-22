"""FastAPI service: health, plugin listing, run submission/history,
findings, pipelines, and reports."""
from __future__ import annotations

from sqlalchemy import select

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from aeptf.core.concurrency import TargetBusyError, TargetCooldownError, get_target_governor
from aeptf.core.config import get_settings
from aeptf.core.executor import (
    UnknownPluginError,
    execute_plugin,
    persist_result,
    run_pipeline,
)
from aeptf.core.jobs import submit_pipeline_run, submit_plugin_run
from aeptf.core.logging import configure_logging, get_logger
from aeptf.core.plugins import get_registry
from aeptf.core.safety import AuthorizationError
from aeptf.database.db import init_db, session_scope
from aeptf.database.models import Finding, Run
from aeptf.modules.reporting.markdown_report import render_pipeline_report, render_run_report

settings = get_settings()
configure_logging(settings)
logger = get_logger("api")

app = FastAPI(
    title="AEPTF",
    description="Automated End-to-End Penetration Testing Framework (authorized assessments only)",
    version="0.2.0",
)


@app.on_event("startup")
def on_startup() -> None:
    init_db(settings)
    get_registry(settings)
    logger.info("AEPTF API started")


class RunRequest(BaseModel):
    target: str = Field(..., description="Exact hostname or IP; must be in safety.approved_targets")
    plugin: str = Field(..., description="Short plugin name, e.g. 'reconnaissance', 'scanning', 'enumeration'")


class PipelineRequest(BaseModel):
    target: str = Field(..., description="Exact hostname or IP; must be in safety.approved_targets")
    pipeline: str | None = Field(
        default=None, description="Named pipeline from configs/*.yml pipelines.definitions; defaults to pipelines.default"
    )


def _http_error_for(exc: Exception) -> HTTPException:
    if isinstance(exc, AuthorizationError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, UnknownPluginError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, (TargetBusyError,)):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, (TargetCooldownError,)):
        return HTTPException(status_code=429, detail=str(exc))
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "app": settings.app.name, "environment": settings.app.environment}


@app.get("/plugins")
def list_plugins() -> dict:
    registry = get_registry(settings)
    return {"plugins": registry.list_plugins()}


@app.get("/pipelines/definitions")
def list_pipeline_definitions() -> dict:
    return {"default": settings.pipelines.default, "definitions": settings.pipelines.definitions}


@app.post("/runs")
def create_run(payload: RunRequest, mode: str = Query("sync", pattern="^(sync|async)$")) -> dict:
    registry = get_registry(settings)

    if mode == "async":
        try:
            return submit_plugin_run(registry, settings, payload.plugin, payload.target)
        except UnknownPluginError as exc:
            raise _http_error_for(exc) from exc

    governor = get_target_governor()
    try:
        with governor.acquire(payload.target, settings.safety.min_seconds_between_runs):
            result = execute_plugin(registry, settings, payload.plugin, payload.target)
    except (AuthorizationError, UnknownPluginError, TargetBusyError, TargetCooldownError) as exc:
        raise _http_error_for(exc) from exc

    with session_scope() as session:
        run = persist_result(session, result)
        return run.to_dict(include_findings=True)


@app.get("/runs")
def list_runs(limit: int = 50, status: str | None = None, target: str | None = None) -> dict:
    limit = max(1, min(limit, 200))
    with session_scope() as session:
        stmt = select(Run).order_by(Run.created_at.desc()).limit(limit)
        if status:
            stmt = stmt.where(Run.status == status)
        if target:
            stmt = stmt.where(Run.target == target)
        rows = session.execute(stmt).scalars().all()
        return {"runs": [row.to_dict() for row in rows]}


@app.get("/runs/{run_id}")
def get_run(run_id: str) -> dict:
    with session_scope() as session:
        run = session.get(Run, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
        return run.to_dict(include_findings=True)


@app.get("/runs/{run_id}/report")
def get_run_report(run_id: str) -> dict:
    with session_scope() as session:
        run = session.get(Run, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
        return {"run_id": run_id, "report_markdown": render_run_report(run)}


@app.get("/findings")
def list_findings(
    limit: int = 100,
    severity: str | None = None,
    target: str | None = None,
) -> dict:
    limit = max(1, min(limit, 500))
    with session_scope() as session:
        stmt = select(Finding).order_by(Finding.created_at.desc()).limit(limit)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if target:
            stmt = stmt.where(Finding.target == target)
        rows = session.execute(stmt).scalars().all()
        return {"findings": [row.to_dict() for row in rows]}


@app.post("/pipelines")
def create_pipeline(payload: PipelineRequest, mode: str = Query("sync", pattern="^(sync|async)$")) -> dict:
    registry = get_registry(settings)

    if mode == "async":
        try:
            return submit_pipeline_run(registry, settings, payload.target, payload.pipeline)
        except KeyError as exc:
            raise _http_error_for(exc) from exc

    governor = get_target_governor()
    try:
        with governor.acquire(payload.target, settings.safety.min_seconds_between_runs):
            with session_scope() as session:
                pipeline_id, pipeline_name, runs = run_pipeline(
                    session, registry, settings, payload.target, payload.pipeline
                )
                run_dicts = [r.to_dict(include_findings=True) for r in runs]
    except (AuthorizationError, UnknownPluginError, KeyError, TargetBusyError, TargetCooldownError) as exc:
        raise _http_error_for(exc) from exc

    return {"pipeline_id": pipeline_id, "pipeline": pipeline_name, "target": payload.target, "runs": run_dicts}


@app.get("/pipelines/{pipeline_id}")
def get_pipeline(pipeline_id: str) -> dict:
    with session_scope() as session:
        rows = (
            session.execute(select(Run).where(Run.pipeline_id == pipeline_id).order_by(Run.created_at.asc()))
            .scalars()
            .all()
        )
        if not rows:
            raise HTTPException(status_code=404, detail=f"Pipeline '{pipeline_id}' not found (or still queued)")
        return {
            "pipeline_id": pipeline_id,
            "pipeline": rows[0].pipeline_name,
            "runs": [row.to_dict(include_findings=True) for row in rows],
        }


@app.get("/pipelines/{pipeline_id}/report")
def get_pipeline_report(pipeline_id: str) -> dict:
    with session_scope() as session:
        rows = (
            session.execute(select(Run).where(Run.pipeline_id == pipeline_id).order_by(Run.created_at.asc()))
            .scalars()
            .all()
        )
        if not rows:
            raise HTTPException(status_code=404, detail=f"Pipeline '{pipeline_id}' not found (or still queued)")
        target = rows[0].target
        return {
            "pipeline_id": pipeline_id,
            "report_markdown": render_pipeline_report(pipeline_id, target, rows),
        }
