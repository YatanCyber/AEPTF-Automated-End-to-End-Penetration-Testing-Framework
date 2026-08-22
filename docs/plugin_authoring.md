# Writing an AEPTF plugin

AEPTF is built so third-party plugins are first-class: the built-in
reconnaissance/scanning/enumeration plugins use the exact same
`AssessmentPlugin` base class you would.

## Quick start

```bash
aeptf new-plugin tls-inspect --category enumeration --description "Checks TLS cert expiry on one host."
```

This creates `aeptf/modules/enumeration/tls_inspect.py` from a template
and prints the import path to add to `configs/default.yml`:

```yaml
plugins:
  enabled:
    - aeptf.modules.enumeration.tls_inspect.TlsInspectPlugin
```

(For a plugin that lives in your own package rather than inside this
repo, just use its real import path -- the registry doesn't care where a
plugin is installed from, only that it's importable and enabled.)

## The contract

```python
from aeptf.core.plugins import AssessmentPlugin, Finding, PluginMeta, PluginResult

class MyPlugin(AssessmentPlugin):
    name = "my-plugin"                       # short name used everywhere (API, CLI, config)
    description = "One line, shown in aeptf list-plugins."
    meta = PluginMeta(
        version="0.1.0",
        requires_binaries=["mytool"],        # checked automatically via check_ready()
        network_scope="single-target",       # documentation only, not enforced
        bounded=True,                        # False = you're asserting this plugin self-limits differently
    )

    def run(self, target: str, settings) -> PluginResult:
        started_at = self._start()
        self.authorize(target, settings)     # MANDATORY, first line. Raises AuthorizationError.

        # ... your bounded action against `target` ...

        return self.finish(
            target=target,
            started_at=started_at,
            finished_at=self._finish(),
            status="success",                # or "error"
            summary="human-readable one-liner",
            data={...},                       # raw output, JSON-serializable
            findings=[Finding(title=..., severity=..., description=..., evidence={...})],
        )
```

### Rules that keep AEPTF's safety model intact

1. **`self.authorize(target, settings)` is the first line of `run()`,
   always.** It raises `AuthorizationError` for anything not in
   `safety.approved_targets`. There's no parameter to skip it and no
   supported pattern where you'd want to.
2. **One fixed action per run.** Don't accept a list of targets, a port
   range, or arbitrary flags from the caller. If your plugin wraps a
   CLI tool, build its argv from constants plus `target` only -- never
   from caller-supplied strings.
3. **Respect the configured ceilings.** If your plugin does something
   with a size or time dimension (ports, paths, requests), read the
   limit from `settings.safety` (add a field there if you need a new
   one) rather than hardcoding it or accepting it as a parameter.
4. **`check_ready()` should never touch the network.** The default
   implementation checks `meta.requires_binaries` against `PATH`;
   override it if you need to check something else (an env var holding
   an API key, for instance), but keep it local and side-effect-free --
   it's called by `/plugins` and `aeptf list-plugins` just to render a
   status, not to run anything.
5. **Findings are for humans, not for machines.** Only add a `Finding`
   for something worth someone's attention; put full raw output in
   `data` instead. Don't put secrets (tokens, session cookies) in
   `Finding.description` or `Finding.evidence` -- findings are what ends
   up in Markdown reports.

## Events

If you want to react to what's happening elsewhere in the framework
(e.g. send a Slack message when a `critical` finding is recorded, or
mirror every denied authorization attempt to a SIEM), don't fork core
code -- subscribe to the event bus:

```python
from aeptf.core.hooks import get_event_bus

def on_run_finished(payload: dict) -> None:
    if payload["status"] == "error":
        ...

get_event_bus().on("run.finished", on_run_finished)
```

See `aeptf/core/hooks.py` for the full list of built-in event names.
Your own plugin can also `get_event_bus().emit("plugin.my-plugin.checkpoint", {...})`
at any point during `run()` -- event names are just strings.

## Testing your plugin

`aeptf.testing` gives you a `Settings` builder and an authorization-denial
assertion so you're not hand-rolling config objects:

```python
from aeptf.testing import make_test_settings, assert_denied_for_unapproved_target
from aeptf.modules.enumeration.tls_inspect import TlsInspectPlugin

def test_denies_unapproved_target():
    settings = make_test_settings(approved_targets=["127.0.0.1"])
    assert_denied_for_unapproved_target(TlsInspectPlugin(), settings, "not-approved.example")

def test_runs_against_approved_target():
    settings = make_test_settings(approved_targets=["127.0.0.1"])
    result = TlsInspectPlugin().run("127.0.0.1", settings)
    assert result.status in {"success", "error"}
```

## Pipelines

Plugins don't know or care which pipelines they're part of. Once your
plugin is registered (enabled + importable), add its short name to any
pipeline in `configs/default.yml`:

```yaml
pipelines:
  definitions:
    default:
      - reconnaissance
      - scanning
      - enumeration
      - my-plugin
    my-plugin-only:
      - my-plugin
```

Run it with `aeptf pipeline --target 127.0.0.1 --name my-plugin-only` or
`POST /pipelines {"target": "127.0.0.1", "pipeline": "my-plugin-only"}`.
