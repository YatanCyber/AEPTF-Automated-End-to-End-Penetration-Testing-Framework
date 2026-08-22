"""Background execution for /runs and /pipelines when a caller opts into
async mode.

This is intentionally a small in-process thread pool, not a distributed
task queue -- it doesn't survive an API process restart, and a job's
progress is only as durable as the database rows it writes as it goes.
That's a real limitation (see docs/notes.md "next milestones" for the
queued-background-jobs item this partially satisfies) but it's enough to
make `/runs` and `/pipelines` non-blocking for a scan that takes the
better part of nmap's timeout, without pulling in Celery/RQ/Redis for a
starter framework.
"""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from aeptf.core.concurrency import TargetBusyError, TargetCooldownError, get_target_governor
from aeptf.core.config import Settings
from aeptf.core.executor import (
    execute_plugin,
    persist_result,
    resolve_pipeline_steps,
    update_run_with_result,
    UnknownPluginError,
)
from aeptf.core.logging import get_logger
from aeptf.core.plugins import PluginRegistry
from aeptf.core.safety import AuthorizationError
from aeptf.database.db import session_scope
from aeptf.database.models import Run

logger = get_logger("jobs")

_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="aeptf-job")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def submit_plugin_run(registry: PluginRegistry, settings: Settings, plugin_name: str, target: str) -> dict:
    """Create a 'queued' Run row immediately, execute in the background,
    and update that same row in place as it progresses. Returns the
    queued row as a dict so the caller has an id to poll."""
    with session_scope() as session:
        run = Run(plugin=plugin_name, target=target, status="queued", created_at=_now())
        session.add(run)
        session.flush()
        session.refresh(run)
        run_dict = run.to_dict()
        run_id = run.id

    _executor.submit(_execute_and_update, registry, settings, run_id, plugin_name, target)
    return run_dict


def _execute_and_update(registry: PluginRegistry, settings: Settings, run_id: str, plugin_name: str, target: str) -> None:
    governor = get_target_governor()
    try:
        with governor.acquire(target, settings.safety.min_seconds_between_runs):
            _mark_status(run_id, "running")
            result = execute_plugin(registry, settings, plugin_name, target)
            with session_scope() as session:
                row = session.get(Run, run_id)
                if row is not None:
                    update_run_with_result(session, row, result)
                else:
                    # Row vanished (e.g. deleted out-of-band) -- fall back
                    # to creating a fresh one so the result isn't lost.
                    persist_result(session, result)
    except AuthorizationError as exc:
        _mark_status(run_id, "denied", error=str(exc))
    except (TargetBusyError, TargetCooldownError) as exc:
        _mark_status(run_id, "error", error=str(exc))
    except UnknownPluginError as exc:
        _mark_status(run_id, "error", error=str(exc))
    except Exception as exc:  # noqa: BLE001 - a job must never crash the pool silently
        logger.exception("Background run %s failed", run_id)
        _mark_status(run_id, "error", error=str(exc))


def _mark_status(run_id: str, status: str, error: str | None = None) -> None:
    with session_scope() as session:
        row = session.get(Run, run_id)
        if row is None:
            return
        row.status = status
        if error:
            row.error = error
        if status == "running":
            row.started_at = _now()
        if status in {"success", "error", "denied"}:
            row.finished_at = _now()


def submit_pipeline_run(
    registry: PluginRegistry, settings: Settings, target: str, pipeline_name: str | None = None
) -> dict:
    """Kick off a pipeline in the background. Returns a pipeline_id right
    away; poll GET /pipelines/{pipeline_id} to see steps land one at a
    time (the framework doesn't pre-create placeholder rows per step,
    since the step list is only known once resolve_pipeline_steps runs)."""
    resolved_name, steps = resolve_pipeline_steps(settings, pipeline_name)
    pipeline_id = str(uuid.uuid4())
    _executor.submit(_run_pipeline_steps, registry, settings, pipeline_id, resolved_name, steps, target)
    return {"pipeline_id": pipeline_id, "pipeline": resolved_name, "target": target, "status": "queued", "steps": steps}


def _run_pipeline_steps(
    registry: PluginRegistry, settings: Settings, pipeline_id: str, pipeline_name: str, steps: list[str], target: str
) -> None:
    governor = get_target_governor()
    try:
        with governor.acquire(target, settings.safety.min_seconds_between_runs):
            for plugin_name in steps:
                result = execute_plugin(registry, settings, plugin_name, target)
                with session_scope() as session:
                    persist_result(session, result, pipeline_id=pipeline_id, pipeline_name=pipeline_name)
    except (AuthorizationError, TargetBusyError, TargetCooldownError, UnknownPluginError) as exc:
        logger.warning("Pipeline %s stopped early: %s", pipeline_id, exc)
    except Exception:  # noqa: BLE001
        logger.exception("Pipeline %s failed", pipeline_id)
