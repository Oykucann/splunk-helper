# splunk-helper

Read-only discovery and cleanup planning for poorly structured Splunk environments,
ahead of a migration to a multisite indexer cluster + search head cluster.

## Project

Language: Python (stdlib only at runtime)
Local tooling: Python 3.9+ (`shx._toml` falls back when `tomllib` is missing)
Remote collector: Splunk's bundled Python or the host python3 (3.6+), stdlib only

## Conventions

- Read `CONTEXT.md` for domain language before starting any task.
- ADR required before any irreversible architectural decision (`docs/adr/`).
- Nothing in this repo may write to, restart, reload or reconfigure a Splunk server.
  See ADR-0001. Tests enforce this for the remote collector.

## Hard safety rules

- No REST calls to any server; everything is read over SSH.
- Never connect to a VIP; always to a node's own address.
- Collect one server at a time; never touch both nodes of an HA group concurrently.
- The remote collector writes nothing on the target host; output is streamed to stdout.
- Secrets are redacted on the target host before leaving it.

## Layout

- `src/shx/remote/collect_remote.py` — single file streamed to targets over SSH (read-only)
- `src/shx/collect/` — `shx-collect`: environment file, sequential SSH collection
- `src/shx/report/` — `shx-report`: one HTML report (servers/service, apps, differences,
  Splunkbase versions, btool server settings)
- `src/shx/conf/` — btool and raw .conf parsers
- `environments/` — per-environment config (gitignored except the example)
- `snapshots/` — collected data and reports (gitignored, never committed)

Keep outputs simple: one HTML file, short notes, no severities or verdicts.
