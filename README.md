# AEPTF — Automated End-to-End Penetration Testing Framework

AEPTF is a Linux-first **framework** — not just a starter app — for
organizing *authorized* security assessments: a plugin SDK third parties
build against, an allowlisted execution path enforced at the base-class
level, configurable pipelines, an event bus for extending behavior
without forking core code, sync and async execution, normalized
findings, persisted run history, a CLI, and Markdown reports.

> Use only against systems you own or are explicitly authorized to
> assess. The exploitation package is deliberately non-operational and
> lab-only (see `aeptf/modules/exploitation/README.md`).

## What makes this a framework, not just a project

- **A real plugin SDK** (`aeptf.core.plugins.AssessmentPlugin`): declared
  capabilities (`PluginMeta`), a `check_ready()` precondition check
  (missing binaries, etc.) surfaced *before* a plugin runs, and a
  normalized `Finding` type separate from raw output. `aeptf new-plugin`
  scaffolds one for you; see `docs/plugin_authoring.md`.
- **An event bus** (`aeptf.core.hooks`): subscribe to `run.started`,
  `run.finished`, `run.denied`, `pipeline.started/finished`,
  `plugin.registered`, etc. to add alerting, audit logging, or
  integrations without touching core code.
- **Configurable pipelines**: named, ordered plugin sequences live in
  `configs/*.yml` under `pipelines.definitions` — add or change a
  pipeline without a code change. Ships three examples: `default`,
  `recon-only`, `web-only`.
- **Sync or async execution**: `POST /runs` and `POST /pipelines` block
  by default; pass `?mode=async` to get an id back immediately and poll
  for completion, backed by an in-process job queue.
- **Per-target concurrency control**: a target can't have two runs in
  flight at once, and an optional `safety.min_seconds_between_runs`
  cooldown throttles how often it can be re-run at all.
- **Normalized findings**, separate from raw plugin output, queryable via
  `GET /findings` / `aeptf findings`, and rendered into reports.
- **A testing harness** (`aeptf.testing`) so plugin authors aren't
  hand-building `Settings` objects to unit test their authorization
  handling.

The safety model underneath all of this hasn't changed: every plugin
still must call `self.authorize()` first, targets are still an exact-match
allowlist with no bypass, and the bounded discovery/scanning/HTTP-metadata
plugins still use fixed, non-configurable-by-request commands.

## Quick start (Linux)

```bash
git clone <your-repository-url> aeptf
cd aeptf
./install.sh
source .venv/bin/activate
aeptf init-db
aeptf serve --reload
```

Open `http://127.0.0.1:8000/docs` for the API documentation.

## Operational workflow

1. Install Nmap on the Linux host (`nmap` is intentionally not installed by `install.sh`):
   ```bash
   sudo apt update && sudo apt install -y nmap
   ```
2. Add exact, explicitly authorized lab hostnames or IPs to `safety.approved_targets`
   in `configs/default.yml`:
   ```yaml
   safety:
     authorization_required: true
     approved_targets:
       - 127.0.0.1
   ```
   This is an exact-match allowlist — no wildcards, no CIDR ranges, no
   request-supplied bypass. See `aeptf/core/safety.py`.
3. Check what's registered and ready before running anything:
   ```bash
   aeptf list-plugins      # shows readiness, e.g. "missing binary: nmap"
   aeptf list-pipelines
   ```
4. Submit one module at a time (sync, blocks until done):
   ```bash
   curl -X POST http://127.0.0.1:8000/runs \
     -H 'Content-Type: application/json' \
     -d '{"target":"127.0.0.1","plugin":"reconnaissance"}'
   ```
   Or async (returns immediately with a pollable id):
   ```bash
   curl -X POST "http://127.0.0.1:8000/runs?mode=async" \
     -H 'Content-Type: application/json' \
     -d '{"target":"127.0.0.1","plugin":"reconnaissance"}'
   ```
5. Retrieve run history at `/runs` (filterable by `status`/`target`), a
   run at `/runs/<id>`, its Markdown report at `/runs/<id>/report`, and
   findings across all runs at `/findings` (filterable by `severity`/`target`).

For a full pipeline, use `POST /pipelines` (optionally `{"pipeline": "web-only"}`
to pick a named pipeline other than the default) or:

```bash
aeptf pipeline --target 127.0.0.1 --name web-only
```

The same history is available from the terminal with `aeptf runs`,
`aeptf findings`, and `aeptf report --run-id <id>` (or `--pipeline-id <id>`).

The three built-in plugins are bounded Nmap host discovery
(`nmap -sn`), a top-100 TCP/light service scan (`nmap --top-ports 100 -sV
--version-intensity 2`), and one HTTP `HEAD` metadata request. They do
not crawl, brute-force, exploit, or accept arbitrary shell commands or
nmap flags from the caller — every command's flags are fixed in code;
only the target and the operator-configured ceilings
(`safety.max_scan_ports`, timeouts, `min_seconds_between_runs`) vary.

## Docker

```bash
docker compose up --build
```

The API is available at `http://localhost:8000`; PostgreSQL is provided
for development. **Change the default database password** in
`docker-compose.yml` before use outside a local environment.

## Layout

```text
aeptf/
├── aeptf/
│   ├── api/                   # FastAPI endpoints
│   ├── core/
│   │   ├── config.py            # YAML + env settings, including pipelines.*
│   │   ├── safety.py            # authorization allowlist gate
│   │   ├── plugins.py           # the Plugin SDK: AssessmentPlugin, PluginMeta, Finding, registry
│   │   ├── hooks.py             # event bus
│   │   ├── concurrency.py       # per-target locking + cooldown
│   │   ├── executor.py          # shared run/pipeline execution + persistence
│   │   ├── jobs.py              # async (background) execution
│   │   └── logging.py
│   ├── database/               # SQLAlchemy models (Run, Finding) + engine
│   ├── modules/
│   │   ├── reconnaissance/     # nmap -sn
│   │   ├── scanning/           # nmap --top-ports
│   │   ├── enumeration/        # HTTP HEAD
│   │   ├── reporting/          # Markdown rendering
│   │   ├── ai_analysis/        # placeholder, not implemented
│   │   └── exploitation/       # placeholder, deliberately not implemented
│   ├── cli.py                  # serve, init-db, list-plugins, list-pipelines,
│   │                            # runs, findings, report, pipeline, new-plugin
│   └── testing.py              # helpers for plugin authors' own test suites
├── configs/default.yml         # safety, plugins, pipelines, reporting
├── docs/
│   ├── notes.md                 # design rationale, known gaps
│   └── plugin_authoring.md     # full guide to writing a plugin
├── tests/
├── Dockerfile
├── docker-compose.yml
├── install.sh
└── pyproject.toml
```

## Adding a module

```bash
aeptf new-plugin my-plugin --category enumeration --description "..."
```

scaffolds `aeptf/modules/enumeration/my_plugin.py` implementing
`AssessmentPlugin` and prints the import path to add to
`plugins.enabled` in `configs/default.yml`. See `docs/plugin_authoring.md`
for the full contract — the short version: `self.authorize(target,
settings)` is the mandatory first line of `run()`, and there is no
supported way to skip it.

## Development status

Implemented in this iteration: the plugin SDK (`PluginMeta`,
`check_ready()`, `Finding`), the event bus, configurable pipelines, sync
+ async execution, per-target locking/cooldown, normalized findings, the
`new-plugin` scaffold command, and a plugin-testing harness.

Still open (see `docs/notes.md`): authenticated target-registration
workflows (managing `approved_targets` via API instead of only
YAML/env), a durable/distributed job queue (the current one is an
in-process thread pool that doesn't survive a process restart),
vulnerability templates for classifying findings, and a dashboard.
