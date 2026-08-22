"""The AEPTF Plugin SDK.

This module is the contract third-party plugin authors build against.
Plugins are enabled explicitly by dotted import path in
configs/default.yml under plugins.enabled. There is no auto-discovery of
arbitrary code on disk: only paths an operator has put in configuration
are ever imported and run.

Minimal plugin::

    from aeptf.core.plugins import AssessmentPlugin, PluginMeta

    class MyPlugin(AssessmentPlugin):
        name = "my-plugin"
        description = "One-line description shown in `aeptf list-plugins`."
        meta = PluginMeta(version="0.1.0", requires_binaries=["mytool"])

        def run(self, target, settings):
            self.authorize(target, settings)   # mandatory, first line
            started = self._start()
            ...
            return self.finish(
                target=target, started_at=started, finished_at=self._finish(),
                status="success", summary="...",
            )

See docs/plugin_authoring.md for the full guide, and run
`aeptf new-plugin <name>` to scaffold one.
"""
from __future__ import annotations

import importlib
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from aeptf.core.config import Settings
from aeptf.core.safety import enforce_authorization, AuthorizationError
from aeptf.core.logging import get_logger
from aeptf.core.hooks import get_event_bus

logger = get_logger("plugins")


@dataclass
class Finding:
    """A single, normalized, human-reviewable observation.

    Findings are how plugins report things worth a human's attention,
    separate from the raw `PluginResult.data` blob. Keep `title` and
    `description` free of secrets (session tokens, cookies, JWTs) --
    findings are what ends up in reports.
    """

    title: str
    severity: str = "info"  # "info" | "low" | "medium" | "high" | "critical"
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        allowed = {"info", "low", "medium", "high", "critical"}
        if self.severity not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}, got {self.severity!r}")


@dataclass
class PluginResult:
    """Normalized output every plugin returns."""

    plugin_name: str
    target: str
    started_at: str
    finished_at: str
    status: str  # "success" | "error"
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    findings: list[Finding] = field(default_factory=list)


@dataclass
class PluginMeta:
    """Declared capabilities of a plugin, checked before it ever runs.

    This is what lets the framework answer "is this plugin usable right
    now" (missing binary, etc.) without executing it, and is a contract
    plugin authors are expected to fill in honestly -- it is not enforced
    against actual behavior, but `/plugins` and `aeptf list-plugins`
    surface it directly to operators deciding what to enable.
    """

    version: str = "0.1.0"
    requires_binaries: list[str] = field(default_factory=list)
    network_scope: str = "single-target"  # e.g. "single-target", "none"
    bounded: bool = True  # False signals a plugin does NOT self-limit request volume


@dataclass
class Readiness:
    ready: bool
    reasons: list[str] = field(default_factory=list)


class AssessmentPlugin(ABC):
    """Base class every assessment module must implement.

    Subclasses must:
      * set `name`, `description`, and ideally `meta`
      * implement `run(target, settings) -> PluginResult`
      * call `self.authorize(target, settings)` as the *first* action inside
        `run`, before touching the network in any way.

    Subclasses may override `check_ready()` to report unmet preconditions
    (e.g. a missing binary) without performing an actual assessment.
    """

    name: str = "unnamed-plugin"
    description: str = ""
    meta: PluginMeta = PluginMeta()

    def authorize(self, target: str, settings: Settings) -> None:
        """Enforce the authorization policy. Raises AuthorizationError."""
        try:
            enforce_authorization(target, settings.safety)
        except AuthorizationError as exc:
            get_event_bus().emit(
                "run.denied", {"plugin": self.name, "target": target, "reason": str(exc)}
            )
            raise
        get_event_bus().emit("run.started", {"plugin": self.name, "target": target})

    @abstractmethod
    def run(self, target: str, settings: Settings) -> PluginResult:
        """Execute the bounded assessment action against `target`."""
        raise NotImplementedError

    def check_ready(self) -> Readiness:
        """Report whether this plugin's declared preconditions are met.

        Default implementation checks `meta.requires_binaries` against
        PATH. Override for anything more specific (e.g. an API key env
        var). This must not touch the network or any target.
        """
        missing = [b for b in self.meta.requires_binaries if shutil.which(b) is None]
        if missing:
            return Readiness(ready=False, reasons=[f"missing binary: {b}" for b in missing])
        return Readiness(ready=True)

    def _start(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _finish(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _emit_finished(self, result: PluginResult) -> PluginResult:
        """Emit `run.finished`. Called automatically by `finish()` below."""
        get_event_bus().emit(
            "run.finished",
            {"plugin": self.name, "target": result.target, "status": result.status},
        )
        return result

    def finish(self, **kwargs: Any) -> PluginResult:
        """Convenience constructor for PluginResult that also emits
        `run.finished`. Prefer this over building PluginResult directly."""
        result = PluginResult(plugin_name=self.name, **kwargs)
        return self._emit_finished(result)


def load_plugin(import_path: str) -> AssessmentPlugin:
    """Import `module.ClassName` and instantiate it."""
    module_path, _, class_name = import_path.rpartition(".")
    if not module_path:
        raise ValueError(f"Invalid plugin import path: {import_path!r}")
    module = importlib.import_module(module_path)
    plugin_cls = getattr(module, class_name)
    if not issubclass(plugin_cls, AssessmentPlugin):
        raise TypeError(f"{import_path} does not implement AssessmentPlugin")
    return plugin_cls()


class PluginRegistry:
    """Loads and holds the set of enabled plugins, keyed by short name."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._plugins: dict[str, AssessmentPlugin] = {}
        self._import_paths: dict[str, str] = {}
        self._import_errors: dict[str, str] = {}
        self._load_enabled()

    def _load_enabled(self) -> None:
        bus = get_event_bus()
        for import_path in self._settings.plugins.enabled:
            try:
                plugin = load_plugin(import_path)
            except Exception as exc:  # noqa: BLE001 - surfaced via list_plugins()
                logger.error("Failed to load plugin %s: %s", import_path, exc)
                self._import_errors[import_path] = str(exc)
                bus.emit("plugin.load_failed", {"import_path": import_path, "error": str(exc)})
                continue
            key = self._short_name(plugin.name)
            self._plugins[key] = plugin
            self._import_paths[key] = import_path
            logger.info("Registered plugin '%s' (%s)", key, import_path)
            bus.emit("plugin.registered", {"name": key, "import_path": import_path})

    @staticmethod
    def _short_name(name: str) -> str:
        return name.strip().lower().replace(" ", "-")

    def get(self, name: str) -> AssessmentPlugin | None:
        return self._plugins.get(self._short_name(name))

    def list_plugins(self) -> list[dict[str, Any]]:
        entries = []
        for key, plugin in self._plugins.items():
            readiness = plugin.check_ready()
            entries.append(
                {
                    "name": key,
                    "description": plugin.description,
                    "import_path": self._import_paths[key],
                    "version": plugin.meta.version,
                    "requires_binaries": plugin.meta.requires_binaries,
                    "network_scope": plugin.meta.network_scope,
                    "bounded": plugin.meta.bounded,
                    "ready": readiness.ready,
                    "ready_reasons": readiness.reasons,
                }
            )
        for import_path, error in self._import_errors.items():
            entries.append(
                {
                    "name": import_path,
                    "description": f"FAILED TO LOAD: {error}",
                    "import_path": import_path,
                    "version": None,
                    "requires_binaries": [],
                    "network_scope": None,
                    "bounded": None,
                    "ready": False,
                    "ready_reasons": [error],
                }
            )
        return entries

    def names(self) -> list[str]:
        return list(self._plugins.keys())


_registry_singleton: PluginRegistry | None = None


def get_registry(settings: Settings | None = None, reload: bool = False) -> PluginRegistry:
    global _registry_singleton
    if _registry_singleton is None or reload:
        from aeptf.core.config import get_settings

        _registry_singleton = PluginRegistry(settings or get_settings())
    return _registry_singleton
