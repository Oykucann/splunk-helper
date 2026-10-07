# splunk-helper

Read-only discovery and cleanup planning for poorly structured Splunk environments,
ahead of a migration to a multisite indexer cluster + search head cluster.

## Project

Language: Python (stdlib only at runtime)
Local tooling: Python 3.11+ (`tomllib`)
Remote collector: must run on Splunk's bundled Python (3.7+), stdlib only

## Conventions

- Read `CONTEXT.md` for domain language before starting any task.
- ADR required before any irreversible architectural decision (`docs/adr/`).
- SPEC required before implementing a new module or major feature (`docs/specs/`).
- Nothing in this repo may write to, restart, reload or reconfigure a Splunk server.
  See ADR-0001. Tests enforce this for the remote collector.

## Hard safety rules

- Never call REST on heavy forwarders (keepalived health-checks splunkd on 8089).
- Never connect to a VIP; always to a node's own address.
- Collect one server at a time; never touch both nodes of an HA group concurrently.
- The remote collector writes nothing on the target host; output is streamed to stdout.
- Secrets are redacted on the target host before leaving it.

## Layout

- `src/shx/remote/collect_remote.py` — single file streamed to targets over SSH
- `src/shx/collect/` — `shx-collect` driver (runs on the engineer's machine); SH REST searches
- `src/shx/transport/rest.py` — read-only REST client with request and SPL guards (SPEC-002)
- `src/shx/conf/`, `src/shx/inventory/` — `shx-compare` (apps and effective config)
- `src/shx/knowledge/` — data files (expected key relationships), no code
- `src/shx/rules/` — `shx-findings`: one module per rule family, registered with `@rule` (SPEC-003)
- `tests/runbuilder.py` — build synthetic runs; every rule needs a positive and a negative case
- `environments/` — per-environment config (gitignored except the example)
- `snapshots/` — collected data (gitignored, never committed)
