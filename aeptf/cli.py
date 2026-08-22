"""aeptf CLI: serve, init-db, list plugins, run a pipeline, view history,
view findings, and scaffold new plugins."""
from __future__ import annotations

from pathlib import Path

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from aeptf.core.concurrency import TargetBusyError, TargetCooldownError, get_target_governor
from aeptf.core.config import get_settings
from aeptf.core.executor import UnknownPluginError, run_pipeline
from aeptf.core.logging import configure_logging
from aeptf.core.plugins import get_registry
from aeptf.core.safety import AuthorizationError
from aeptf.database.db import init_db, session_scope
from aeptf.database.models import Finding, Run
from aeptf.modules.reporting.markdown_report import render_pipeline_report, render_run_report

app = typer.Typer(help="AEPTF: Automated End-to-End Penetration Testing Framework")
console = Console()


@app.command()
def serve(
    host: str | None = typer.Option(None, help="Override configured host"),
    port: int | None = typer.Option(None, help="Override configured port"),
    reload: bool = typer.Option(False, help="Enable auto-reload for development"),
) -> None:
    """Start the FastAPI service."""
    settings = get_settings()
    uvicorn.run(
        "aeptf.api.app:app",
        host=host or settings.app.host,
        port=port or settings.app.port,
        reload=reload,
    )


@app.command("init-db")
def init_db_cmd() -> None:
    """Create database tables."""
    settings = get_settings()
    configure_logging(settings)
    init_db(settings)
    console.print("[green]Database initialized.[/green]")


@app.command("list-plugins")
def list_plugins_cmd() -> None:
    """List enabled plugins, their declared capabilities, and readiness."""
    settings = get_settings()
    registry = get_registry(settings)
    table = Table(title="AEPTF Plugins")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Ready")
    table.add_column("Requires")
    table.add_column("Description")
    for entry in registry.list_plugins():
        ready = "[green]yes[/green]" if entry.get("ready") else "[red]no[/red]"
        requires = ", ".join(entry.get("requires_binaries") or []) or "-"
        table.add_row(
            entry["name"],
            str(entry.get("version") or "-"),
            ready,
            requires,
            entry["description"],
        )
    console.print(table)
    for entry in registry.list_plugins():
        if not entry.get("ready") and entry.get("ready_reasons"):
            console.print(f"  [yellow]{entry['name']}:[/yellow] {'; '.join(entry['ready_reasons'])}")


@app.command("list-pipelines")
def list_pipelines_cmd() -> None:
    """List named pipelines available in configuration."""
    settings = get_settings()
    table = Table(title="AEPTF Pipelines")
    table.add_column("Name")
    table.add_column("Steps")
    for name, steps in settings.pipelines.definitions.items():
        marker = " (default)" if name == settings.pipelines.default else ""
        table.add_row(name + marker, " -> ".join(steps))
    console.print(table)


@app.command("runs")
def runs_cmd(
    limit: int = typer.Option(20, help="Max number of runs to show"),
    status: str | None = typer.Option(None, help="Filter by status"),
    target: str | None = typer.Option(None, help="Filter by target"),
) -> None:
    """List recent runs from history."""
    from sqlalchemy import select

    with session_scope() as session:
        stmt = select(Run).order_by(Run.created_at.desc()).limit(limit)
        if status:
            stmt = stmt.where(Run.status == status)
        if target:
            stmt = stmt.where(Run.target == target)
        rows = session.execute(stmt).scalars().all()
        table = Table(title="AEPTF Run History")
        table.add_column("ID")
        table.add_column("Plugin")
        table.add_column("Target")
        table.add_column("Status")
        table.add_column("Findings")
        table.add_column("Created")
        for row in rows:
            table.add_row(
                row.id[:8],
                row.plugin,
                row.target,
                row.status,
                str(len(row.findings)),
                row.created_at.isoformat() if row.created_at else "",
            )
        console.print(table)


@app.command("findings")
def findings_cmd(
    limit: int = typer.Option(50, help="Max number of findings to show"),
    severity: str | None = typer.Option(None, help="Filter by severity"),
    target: str | None = typer.Option(None, help="Filter by target"),
) -> None:
    """List recorded findings across all runs."""
    from sqlalchemy import select

    with session_scope() as session:
        stmt = select(Finding).order_by(Finding.created_at.desc()).limit(limit)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if target:
            stmt = stmt.where(Finding.target == target)
        rows = session.execute(stmt).scalars().all()
        table = Table(title="AEPTF Findings")
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Target")
        table.add_column("Plugin")
        table.add_column("Run")
        severity_color = {"info": "cyan", "low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}
        for row in rows:
            color = severity_color.get(row.severity, "white")
            table.add_row(f"[{color}]{row.severity}[/{color}]", row.title, row.target, row.plugin, row.run_id[:8])
        console.print(table)


@app.command("report")
def report_cmd(
    run_id: str | None = typer.Option(None, help="Run ID (or unambiguous prefix) to report on"),
    pipeline_id: str | None = typer.Option(None, help="Pipeline ID to report on"),
) -> None:
    """Print a Markdown report for a run or pipeline."""
    from sqlalchemy import select

    if not run_id and not pipeline_id:
        console.print("[red]Provide --run-id or --pipeline-id[/red]")
        raise typer.Exit(code=1)

    with session_scope() as session:
        if pipeline_id:
            rows = (
                session.execute(select(Run).where(Run.pipeline_id.like(f"{pipeline_id}%")).order_by(Run.created_at.asc()))
                .scalars()
                .all()
            )
            if not rows:
                console.print(f"[red]No pipeline found matching '{pipeline_id}'[/red]")
                raise typer.Exit(code=1)
            console.print(render_pipeline_report(rows[0].pipeline_id, rows[0].target, rows))
            return

        rows = session.execute(select(Run).where(Run.id.like(f"{run_id}%"))).scalars().all()
        if not rows:
            console.print(f"[red]No run found matching '{run_id}'[/red]")
            raise typer.Exit(code=1)
        if len(rows) > 1:
            console.print(f"[red]'{run_id}' is ambiguous, matches {len(rows)} runs[/red]")
            raise typer.Exit(code=1)
        console.print(render_run_report(rows[0]))


@app.command("pipeline")
def pipeline_cmd(
    target: str = typer.Option(..., help="Exact hostname/IP; must be in safety.approved_targets"),
    name: str | None = typer.Option(None, "--name", help="Named pipeline from configs/*.yml; defaults to pipelines.default"),
) -> None:
    """Run a named pipeline (default: reconnaissance -> scanning -> enumeration) against one authorized target."""
    settings = get_settings()
    configure_logging(settings)
    init_db(settings)
    registry = get_registry(settings)
    governor = get_target_governor()

    try:
        with governor.acquire(target, settings.safety.min_seconds_between_runs):
            with session_scope() as session:
                pipeline_id, resolved_name, runs = run_pipeline(session, registry, settings, target, name)
                for run in runs:
                    color = "green" if run.status == "success" else "red"
                    console.print(f"  [{color}]{run.plugin}[/{color}]: {run.summary}")
    except AuthorizationError as exc:
        console.print(f"[red]Authorization denied: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    except (UnknownPluginError, KeyError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    except (TargetBusyError, TargetCooldownError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    console.print(f"[bold green]Done.[/bold green] Pipeline '{resolved_name}' ({pipeline_id})")
    console.print(f"View with: aeptf report --pipeline-id {pipeline_id[:8]}")


_PLUGIN_TEMPLATE = '''"""{description}

Generated by `aeptf new-plugin`. Fill in run() below. Remember:
  * self.authorize(target, settings) MUST be the first thing run() does.
  * Keep the action bounded -- one fixed command/request per run, no
    caller-controlled flags, no loops over a range of hosts.
  * Only import third-party dependencies you've added to pyproject.toml.
"""
from __future__ import annotations

from aeptf.core.config import Settings
from aeptf.core.plugins import AssessmentPlugin, Finding, PluginMeta, PluginResult
from aeptf.core.logging import get_logger

logger = get_logger("{module_logger}")


class {class_name}(AssessmentPlugin):
    name = "{short_name}"
    description = "{description}"
    meta = PluginMeta(
        version="0.1.0",
        requires_binaries=[],   # e.g. ["nmap"] -- checked automatically before run()
        network_scope="single-target",
    )

    def run(self, target: str, settings: Settings) -> PluginResult:
        started_at = self._start()
        self.authorize(target, settings)  # raises AuthorizationError if not approved

        readiness = self.check_ready()
        if not readiness.ready:
            return self.finish(
                target=target,
                started_at=started_at,
                finished_at=self._finish(),
                status="error",
                summary="Plugin preconditions not met.",
                error="; ".join(readiness.reasons),
            )

        # TODO: replace with your bounded assessment action.
        summary = f"{{self.name}} ran against {{target}} (not yet implemented)."

        return self.finish(
            target=target,
            started_at=started_at,
            finished_at=self._finish(),
            status="success",
            summary=summary,
            data={{}},
            findings=[],  # append Finding(...) instances for anything worth a human's review
        )
'''


@app.command("new-plugin")
def new_plugin_cmd(
    name: str = typer.Argument(..., help="Plugin short name, e.g. 'tls-inspect' (used for class name and file name)"),
    category: str = typer.Option(
        "enumeration",
        "--category",
        help="Which aeptf/modules/<category>/ package to create it in (reconnaissance, scanning, enumeration, or a new one)",
    ),
    description: str = typer.Option("TODO: describe what this plugin does.", help="One-line description"),
) -> None:
    """Scaffold a new plugin: creates aeptf/modules/<category>/<name>.py
    implementing AssessmentPlugin, and prints the config line to enable it."""
    slug = name.strip().lower().replace(" ", "-").replace("_", "-")
    module_name = slug.replace("-", "_")
    class_name = "".join(part.capitalize() for part in slug.split("-")) + "Plugin"

    package_dir = Path("aeptf") / "modules" / category
    if not package_dir.exists():
        console.print(f"[yellow]Creating new module package {package_dir}[/yellow]")
        package_dir.mkdir(parents=True, exist_ok=True)
        (package_dir / "__init__.py").write_text("")

    target_file = package_dir / f"{module_name}.py"
    if target_file.exists():
        console.print(f"[red]{target_file} already exists.[/red]")
        raise typer.Exit(code=1)

    content = _PLUGIN_TEMPLATE.format(
        description=description,
        module_logger=f"{category}.{module_name}",
        class_name=class_name,
        short_name=slug,
    )
    target_file.write_text(content)

    import_path = f"aeptf.modules.{category}.{module_name}.{class_name}"
    console.print(f"[green]Created {target_file}[/green]")
    console.print("Add it to configs/default.yml under plugins.enabled:")
    console.print(f"  - {import_path}")
    console.print("Then run: aeptf list-plugins")


if __name__ == "__main__":
    app()
