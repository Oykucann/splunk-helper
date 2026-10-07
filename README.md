# splunk-helper

A **read-only** toolkit that inspects poorly structured Splunk environments and surfaces their
problems. The goal is to clean up content (apps, inputs, configuration) in environments whose
sites run independently, before moving them to a multisite indexer cluster with a search head
cluster.

The tool **finds; it does not fix.** It never writes to, restarts or reloads a server.

## What it produces

| Command | Output |
|---|---|
| `shx-collect` | A redacted configuration snapshot per server, plus REST search results from the search heads |
| `shx-inventory` | Per-server app and input inventory; suggested HA groups, VIPs and `pull_apps` from keepalived |
| `shx-compare` | App and configuration comparison: inside HA groups, within a site, site1 ↔ site2 |
| `shx-findings` | Findings ordered by severity (production risk, data integrity, retention, SHC blockers, security, …) |

## Safety guarantees

- Snapshots are taken by one script streamed over SSH to stdin (`splunk cmd python3 -`).
  Nothing is installed or written on the server. Tests verify at AST level that the script
  is read-only.
- Passwords, tokens, `$7$` values and S3 keys are redacted **before leaving the server**. A
  per-run fingerprint is kept so identical secrets can still be compared.
- **No REST calls to heavy forwarders** (keepalived health-checks port 8089). REST goes only
  to search heads, with a token from a read-only role; tokens with write capabilities are
  refused. Only `GET` and `oneshot` searches are allowed; commands such as `collect`,
  `outputlookup`, `delete`, and macros, are blocked before anything is sent.
- VIPs are never targeted; servers are collected one at a time (HA members last).
- From Enterprise Security and other large vendor apps only `local/` and version information
  are collected.

Details: [ADR-0001](docs/adr/ADR-0001-read-only-collection.md),
[SPEC-002](docs/specs/SPEC-002-sh-rest-searches.md).

## Requirements

- **Python 3.11+** on the machine running the tool. No extra packages (standard library only).
- SSH to the targets with a key (default) or a password (`ssh_auth = "password"`, ssh prompts
  per server), and passwordless `sudo -n -u splunk` (or connect directly as the `splunk` user).
- For REST: a user with a read-only role on each search head, with a token (default) or a
  password (`rest_auth = "password"`), see [docs/readonly-role.md](docs/readonly-role.md).
  Without a CA file, set `rest_verify_tls = false` (lab only).

## Quick start

```bash
git clone https://github.com/Oykucann/splunk-helper.git && cd splunk-helper
cp environments/example.toml environments/<env>.toml   # gitignored, never committed
```

For the first pass each server only needs `name`, `host` (the node's own address, **not a
VIP**), `role` and `site`. HA groups and `pull_apps` are suggested from the inventory later.

```bash
export PYTHONPATH=src
export SHX_TOKEN_SITE1='<read-only token>'

# 1. See what would run (no connections)
python3 -m shx.collect environments/<env>.toml --dry-run

# 2. Access and permission check (collects nothing)
python3 -m shx.collect environments/<env>.toml --check

# 3. Pilot: one server, a pull HF first
python3 -m shx.collect environments/<env>.toml --no-rest --only <pull-hf>

# 4. Full collection (SSH + search head REST); prints the run directory at the end
python3 -m shx.collect environments/<env>.toml
RUN=$(ls -td snapshots/<env>/*/ | head -1)

# 5. Inventory and suggestions
python3 -m shx.inventory.inventory_cli "$RUN"
#    review reports/suggested_env.toml and add it to the environment file

# 6. Comparison and findings (no recollection needed)
python3 -m shx.inventory.cli "$RUN" --env environments/<env>.toml
python3 -m shx.rules.cli "$RUN" --env environments/<env>.toml
```

After `pip install -e .` the same commands are available as `shx-collect`, `shx-inventory`,
`shx-compare` and `shx-findings`.

## Environment file

| Field | Meaning |
|---|---|
| `name` | Environment name; snapshots go to `snapshots/<name>/<run_id>/` |
| `vips` | keepalived/haproxy VIPs; never connected to |
| `[defaults]` | `ssh_user`, `ssh_auth` (`key`/`password`), `ssh_key`, `run_as`, `splunk_home` (default `/data/splunk`), `ssh_options`, `timeout_seconds`, `btool`, `local_only_apps`, `rest_auth` (`token`/`password`), `rest_port`, `rest_scheme`, `rest_verify_tls`, `rest_ca_file` |
| `[[servers]]` `name`, `host`, `role`, `site` | Role: `sh`, `cm`, `ds`, `deployer`, `idx`, `hf` |
| `ha_group` | HFs serving the same push inputs behind one VIP (a keepalived pair, an haproxy pool) |
| `pull_apps` | An HA member that also runs DB Connect / scripted inputs on its own address: the apps owning them |
| `also_roles` | Extra roles on the same instance (e.g. SH + CM in a lab). Collected once; reported as an info finding |
| `rest_token_env` / `rest_token_file` | `sh` only; the token lives in an environment variable or a separate file |
| `rest_username` / `rest_password_env` | `sh` only, with `rest_auth = "password"`; the password comes from the variable or is prompted once per run, never written |
| `allow_privileged_token` | Lab only: accept a token with write capabilities |

Example: [environments/example.toml](environments/example.toml).

## Outputs

Each collection lives in `snapshots/<env>/<run_id>/` (`run_id` is a UTC timestamp such as
`20261007T093015Z`). `snapshots/` is never committed.

| File | Content |
|---|---|
| `run.json` | Which servers were collected, success/failure, REST search status |
| `<server>.tar.gz` | Redacted `.conf`/`.meta` files, btool output, `manifest.json` (app versions, file index, path checks) |
| `<server>.stderr.log` | SSH-side errors and warnings |
| `<sh>.rest.json` | Search head REST search results |
| `reports/inventory.md`, `inputs.csv`, `apps.csv`, `suggested_env.toml` | Inventory |
| `reports/comparison_report.md`, `conf_differences.csv`, `app_differences.csv` | Comparison |
| `reports/findings.md`, `findings.csv`, `findings.json` | Findings |

In findings, **proven** means backed by configuration or log evidence; **suspected** means
inferred and should be verified before acting. Rules that could not run are listed as
`not_applicable` / `insufficient_data`, never as passed. Finding ids are stable across runs.

Rule catalog: [SPEC-003](docs/specs/SPEC-003-rules.md).

## Documentation

- [CONTEXT.md](CONTEXT.md) — domain terms (HA group, pull/push input, drift, …)
- [docs/adr/](docs/adr/) — architectural decisions
- [docs/specs/](docs/specs/) — SPEC-001 discovery and comparison, SPEC-002 REST, SPEC-003 rules,
  SPEC-004 inventory workflow

## Development

```bash
python3 -m pytest -q
```

- The remote script (`src/shx/remote/collect_remote.py`) must run on Splunk's bundled Python
  (3.7+) with the standard library only; adding a write, delete or network call breaks
  `tests/test_remote_guard.py`.
- New rules are registered with `@rule(...)` under `src/shx/rules/`; build a synthetic run with
  `tests/runbuilder.py` and test a positive and a negative case.
- Write a SPEC before a new module or major feature, and an ADR before an irreversible decision.

## Known limits

- haproxy pools cannot be discovered (haproxy hosts are not collected); set `ha_group` by hand.
- Enterprise Security KV store content (notable status, assets/identities) is not collected.
- Search-time behaviour is judged from btool's global view; app/user-context precedence is not
  modelled.
- Some `_internal` field names (DB Connect, `event_message`) vary by version; the affected search
  may return nothing without affecting the others.
