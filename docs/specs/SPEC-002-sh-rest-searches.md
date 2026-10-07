# SPEC-002: Search head REST collection

## Goal

Runtime facts that files cannot show: which inputs actually produce data, which scripts and
DB Connect inputs fail, which HF carries which sourcetype, which UFs connect where, index
size/age/freeze activity, and knowledge-object usage. All from the search head, per site.

## Safety (extends ADR-0001)

- REST targets only servers with role `sh`. Configuring `rest_*` on another role is an error.
- Auth is a bearer token (from an environment variable or a file) or, with
  `rest_auth = "password"`, basic auth for `rest_username` with the password from an environment
  variable or a terminal prompt. Credentials are never written to the TOML, run files or logs.
  The capability check below applies to either.
- The client allows `GET` on `/services/...` and `/servicesNS/...`, and `POST` only to
  `/services/search/jobs` with `exec_mode=oneshot`. Anything else raises before sending.
- Every SPL string passes a guard before sending: no backtick macros, and no command from
  the deny list (`collect`, `outputlookup`, `outputcsv`, `delete`, `sendemail`, `sendalert`,
  `script`, `run`, `runshellscript`, `map`, `savedsearch`, `tscollect`, `mcollect`,
  `meventcollect`, `summaryindex`, `outputtext`, `dump`, ...).
- Before any search, `GET /services/authentication/current-context` is checked. If the token's
  capabilities include write/admin capabilities the run stops, unless the environment sets
  `allow_privileged_token = true` for that server (lab only).
- `| rest` fan-out goes to search peers (indexers). Peers whose name or host matches a
  configured `hf` server are excluded, so no REST call reaches an HF through distributed search.
- TLS verification is on by default (`rest_verify_tls`, `rest_ca_file`).

## Configuration

```toml
[[servers]]
name = "sh01"
host = "10.0.1.10"
role = "sh"
site = "site1"
rest_token_env = "SHX_TOKEN_SITE1"   # or rest_token_file = "~/.shx/site1.token"
# rest_port = 8089, rest_scheme = "https", rest_verify_tls = true, rest_ca_file = "..."
```

## Searches (`src/shx/collect/searches.py`)

| id | Source | Window | Used for |
|---|---|---|---|
| `server_info` | GET server/info | — | SH version, roles |
| `search_peers` | GET search/distributed/peers | — | peer list, HF exclusion |
| `indexes` | `\| rest /services/data/indexes` on peers | — | size, min/max time, limits, remotePath, frozen settings |
| `freeze_events` | `_internal` BucketMover | 30d | deletion without archive (proven) |
| `sourcetype_by_forwarder` | `_internal` metrics per_sourcetype_thruput | 7d | which HF carries which sourcetype; duplicates |
| `host_by_forwarder` | `_internal` metrics per_host_thruput | 7d | origin hosts per HF; duplicate collection |
| `tcpin_connections` | `_internal` metrics tcpin_connections | 7d | UF → HF mapping, UF versions |
| `data_last_seen` | `tstats` by index, sourcetype, host | 7d | inputs with no data |
| `exec_errors` | `_internal` ExecProcessor ERROR | 7d | failing scripted inputs |
| `dbx_jobs` | `_internal` dbx_job_metrics | 7d | failing / idle DB Connect inputs |
| `blocked_queues` | `_internal` metrics queue blocked | 7d | overloaded HFs |
| `scheduler_runs` | `_internal` scheduler | 30d | saved search usage, skipped searches |
| `dashboard_views` | `_internal` splunk_web_access | 30d | dashboard usage |

Message samples in results pass a key=value secret mask before they are written.

## Output

`snapshots/<env>/<run_id>/<server>.rest.json`:
`{"context": {...}, "searches": {id: {spl, earliest, ok, results, messages, error, seconds}}}`.
`run.json` records per-server REST status. A failed search does not stop the others.

## CLI

`shx-collect env.toml` runs SSH collection, then REST for every `sh` with a token.
`--no-rest` / `--rest-only` select one part.
