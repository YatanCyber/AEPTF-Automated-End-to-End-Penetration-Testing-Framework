# Development notes

## Design principles

- **Allowlist, not denylist.** `safety.approved_targets` is the only path
  to authorizing a target. There is no runtime bypass, no wildcard
  matching, and no way to authorize a target from an API request body.
- **The SDK enforces the gate, not each plugin's discipline.**
  `AssessmentPlugin.authorize()` is what raises `AuthorizationError` and
  emits `run.denied`; every plugin (built-in or third-party) calls the
  same method. There's no per-plugin reimplementation of the check to
  audit for drift.
- **Bounded plugins.** Each plugin does exactly one thing (one `nmap -sn`,
  one top-N port scan, one HTTP HEAD) with a fixed, non-configurable-by-request
  flag set. Ceilings like `max_scan_ports` live in configuration, not in
  request payloads, so a single API call can't quietly turn into an
  unbounded scan.
- **Everything is recorded, including denials.** Async denials persist a
  `Run` row with `status="denied"` and the reason in `error`, so a
  polling client (or an auditor reading `/runs`) sees the denial instead
  of the row just... not existing. The synchronous path still returns an
  immediate HTTP 403 for a faster feedback loop, without a DB row for
  that call, since the caller already has the reason in the response.
- **Extensibility without forking.** The event bus
  (`aeptf.core.hooks`) exists so alerting, audit logging, or
  integrations with other systems can be added by subscribing to events
  (`run.finished`, `run.denied`, etc.) instead of editing
  `aeptf/core/plugins.py` or `aeptf/api/app.py`.
- **Configuration over code for anything an operator should be able to
  change without a deploy**: which plugins are enabled, what a pipeline
  runs and in what order, and the safety ceilings, all live in
  `configs/*.yml`.

## What shipped in this iteration

- Plugin SDK: `PluginMeta` (declared capabilities), `check_ready()`
  (precondition check surfaced via `/plugins` and `aeptf list-plugins`
  before a plugin ever runs), and `Finding` (normalized output, separate
  from raw `data`).
- Event bus (`aeptf.core.hooks`) with built-in events for plugin
  registration/load failure and run/pipeline lifecycle.
- Configurable, named pipelines (`pipelines.definitions` in config)
  replacing the previous hardcoded 3-step pipeline.
- Async execution (`?mode=async` on `/runs` and `/pipelines`) backed by
  an in-process `ThreadPoolExecutor`, with the original placeholder `Run`
  row updated in place (not replaced) so a client's id stays valid across
  the queued -> running -> success/error/denied lifecycle.
- Per-target locking (`aeptf.core.concurrency.TargetGovernor`) so two
  runs can't execute against the same target simultaneously, plus an
  optional cooldown between runs on the same target.
- Normalized `Finding` model + `GET /findings` / `aeptf findings`, fed by
  the two built-in plugins that have something worth flagging (notable
  open ports in `scanning`, missing security headers in `enumeration`).
- `aeptf new-plugin` scaffold command and `docs/plugin_authoring.md`.
- `aeptf.testing` helper module for plugin authors' own test suites.

## Known gaps / next milestones

1. **Authenticated target-registration workflow**, so `approved_targets`
   can be managed via API (with an approval step) instead of only
   YAML/env.
2. **A durable job queue.** The current async path is an in-process
   thread pool: it does not survive an API process restart, and job
   state lives only in the `runs` table (a queued job whose process dies
   stays "queued" forever with nothing to resume it). Swapping in
   Celery/RQ/arq with a real broker is the natural next step once this
   needs to run unattended.
3. **Vulnerability templates** for classifying findings (severity
   rationale, CWE/CVE references) beyond the free-text `severity` string
   findings carry today.
4. **A dashboard** (read-only at first) over `/runs`, `/pipelines`, and
   `/findings`.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

None of the test files touch the network or require `nmap` to be
installed:

- `tests/test_safety.py` — the authorization allowlist gate.
- `tests/test_plugins.py` — registry loading, `PluginMeta`/readiness
  reporting, and that `run()` emits events on denial.
- `tests/test_hooks.py` — the event bus in isolation.
- `tests/test_concurrency.py` — per-target locking and cooldown.
- `tests/test_pipelines.py` — named-pipeline resolution.
- `tests/test_scaffold.py` — `aeptf new-plugin` generates an importable,
  correctly-shaped plugin file and refuses to overwrite an existing one.
