"""A small synchronous event bus.

This is the framework's primary extension point for anyone who wants to
react to what AEPTF is doing without forking core code: alerting on
denied authorizations, streaming run results to another system, writing
custom audit logs, etc. Handlers are called in registration order,
in-process, and synchronously -- a slow or raising handler will slow down
or interrupt the run that triggered it, so handlers should be fast and
should catch their own exceptions if that matters to the caller.

Built-in events (see aeptf.core.plugins and aeptf.core.safety for where
they're emitted):

    plugin.registered      {"name": str, "import_path": str}
    plugin.load_failed     {"import_path": str, "error": str}
    run.started             {"plugin": str, "target": str}
    run.finished            {"plugin": str, "target": str, "status": str}
    run.denied               {"plugin": str, "target": str, "reason": str}
    pipeline.started        {"pipeline_id": str, "pipeline": str, "target": str}
    pipeline.finished       {"pipeline_id": str, "pipeline": str, "target": str}

Third-party plugins are free to emit their own events (e.g.
"plugin.myplugin.checkpoint") -- names are just strings, there is no
fixed registry to update.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable

from aeptf.core.logging import get_logger

logger = get_logger("events")

Handler = Callable[[dict[str, Any]], None]


class EventBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = defaultdict(list)

    def on(self, event_name: str, handler: Handler) -> None:
        """Register `handler(payload: dict)` to run when `event_name` fires."""
        self._handlers[event_name].append(handler)

    def off(self, event_name: str, handler: Handler) -> None:
        try:
            self._handlers[event_name].remove(handler)
        except ValueError:
            pass

    def emit(self, event_name: str, payload: dict[str, Any] | None = None) -> None:
        payload = payload or {}
        for handler in list(self._handlers.get(event_name, [])):
            try:
                handler(payload)
            except Exception:  # noqa: BLE001 - a bad handler must not break AEPTF
                logger.exception("Event handler for '%s' raised", event_name)

    def clear(self, event_name: str | None = None) -> None:
        if event_name is None:
            self._handlers.clear()
        else:
            self._handlers.pop(event_name, None)


_bus_singleton = EventBus()


def get_event_bus() -> EventBus:
    """Return the process-wide event bus."""
    return _bus_singleton
