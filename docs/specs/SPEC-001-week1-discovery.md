# SPEC-001: Week-1 discovery

## Goal

In one week, for one environment, produce an inventory, a findings report and a draft
target placement for every app — enough to decide the cleanup order.

## Out of scope (week 1)

Package generation, Docker lab, decision ledger, precedence engine, forced-command hardening.

## Components

### Remote collector (`src/shx/remote/collect_remote.py`) — day 1

Runs as `splunk cmd python3 - [args]`. Python 3.7 compatible, stdlib only.

Streams a `tar.gz` to stdout containing:

| Path in archive | Content |
|---|---|
| `manifest.json` | host, time, splunk_home, version, `splunk.secret` sha256, file index, redaction counts, errors, path checks |
| `etc/...` | Every `*.conf` and `*.meta` under the scanned roots, redacted |
| `btool/<conf>.txt` | `splunk btool <conf> list --debug`, redacted (unless `--no-btool`) |
| `system/keepalived.conf`, `system/haproxy.cfg` | If readable, redacted |

Scanned roots under `$SPLUNK_HOME/etc`: `system/local`, `apps`, `deployment-apps`,
`manager-apps`, `master-apps`, `peer-apps`, `slave-apps`, `shcluster/apps`, `users`.

Local-only apps (Enterprise Security and its SA/DA apps, MLTK, Splunk built-ins, plus
`local_only_apps` patterns from the environment file): only `default/app.conf`, `local/`,
`metadata/` and the `lookups/` index are collected, with a file-count/size summary in
`manifest.local_only_apps`. btool lines sourced from their `default/` are dropped (stanza
headers kept). `Splunk_TA_ForIndexers` and look-alike customer apps are collected in full.

SmartStore (`remote.s3.access_key` / `secret_key`) and other `*secret*` / `*access_key`
values are redacted like any other secret.

Non-conf files (scripts, lookups, binaries) are indexed in the manifest with size, mode,
owner, mtime and sha256 — never copied. Text files under `bin/` are scanned for
suspected secrets; only line numbers and the matched key name are recorded.

Path checks: for every `[monitor://...]` and `[script://...]` stanza found, whether the
target path (up to the first wildcard) exists on the host.

`--check` mode prints a small JSON (identity, version, readable roots) and exits.

Limits: per-file 5 MB, total 300 MB, btool 60 s per conf; exceeded items are listed in
`manifest.errors`. Process runs at `nice 19`.

### Driver (`shx-collect`) — day 1

Reads `environments/<name>.toml`, collects servers sequentially into
`snapshots/<env>/<run_id>/<server>.tar.gz`, and refuses VIP targets.

### App inventory and comparison (`shx-compare`)

Every app directory under an app root gets a `manifest.apps` entry: version
(`[launcher] version`, local overriding default, plus `app.manifest` version), build, label,
author, package id, install state, and three fingerprints:

- `content_sha` — everything except `local/` and `metadata/local.meta` (full apps only)
- `content_shape` — same set, path + size only (all apps, incl. local-only ES apps)
- `local_sha` — `local/` + `metadata/local.meta`

`shx-compare <run_dir>` compares at three levels and writes `apps.csv`,
`app_differences.csv` and the app part of `comparison_report.md`:

| Level | Members | Presence differences | Severity |
|---|---|---|---|
| `ha_group` | servers in one HA group, installed roots | reported | high |
| `site` | same site + role, all roots | not for `hf` (pull vs push differ) | medium/info |
| `cross_site` | same role, each site as the union of its servers | reported | medium/info |

Difference kinds: `presence`, `version`, `content` (same version, different shipped
content — compared by sha when all sides have it, else by shape), `state`, `local`.

### Config comparison (`shx-compare`)

Effective configuration comes from the btool dumps (`src/shx/conf/btool.py`), keyed by
conf → stanza → key with the source file of each value. Same three levels as apps:

| Level | Confs compared |
|---|---|
| `ha_group` | every collected btool conf (inputs, props, outputs, …) |
| `site` | system confs: server, web, limits, authentication, authorize, distsearch, outputs, deploymentclient, health, alert_actions, plus instance facts |
| `cross_site` | system confs + indexes |

A key is compared only if at least one member sets it outside `etc/system/default`.
Booleans and whitespace are normalised. Instance facts (`splunk_version`,
`splunk_secret_sha256`) are compared as pseudo-conf `_instance`.

`src/shx/knowledge/conf_expectations.toml` says how each key should relate
(`per_server`, `per_site`, `must_match`, `ignore`; default `should_match`). Severity:

- **high** — `must_match` differs (cluster/SHC keys, TLS/CA, KV store engine, Splunk version,
  web serving), or any difference inside an HA group
- **decision** — `per_site` differs across sites: legitimate for independent sites today,
  must be unified for the multisite target (cluster manager, site, indexer lists, license)
- **medium** — anything else that differs

Output: `conf_differences.csv` and the configuration part of `comparison_report.md`.

### Index storage and retention (rules, day 3)

Environments differ: some use SmartStore (S3), some only local disk; retention is either
effectively unlimited, or limited with no frozen archive (buckets are deleted when they
freeze). Inputs: CM `manager-apps` indexes.conf, btool `indexes`/`server` from one indexer
per site (role `idx`), and SH searches. Nothing here assumes S3 exists.

**Storage mode** is decided per index from effective config, never per environment:

- `smartstore` — `remotePath` set (directly or via `[default]` / a `volume:` with
  `storageType = remote`)
- `local` — no `remotePath`

Rules marked *(both)* run for every index; the others only for indexes in that mode. A rule
with no index in its mode is reported as "not applicable", not as passed.

1. **Deletion without archive** *(both)* — a size or time limit applies and there is no
   `coldToFrozenDir` / `coldToFrozenScript`. Proven when `_internal` shows freeze events.
2. **Unbounded growth** *(both)* — no explicit `frozenTimePeriodInSecs` (6-year default) and
   no effective size limit. Local: disk-full risk (compare with volume/partition limits).
   SmartStore: S3 cost growth. Report actual oldest event and size per index.
3. **Ineffective limit** — a limit that the index's mode ignores:
   - `smartstore`: `maxTotalDataSizeMB`, `homePath.maxDataSizeMB`, `coldPath.maxDataSizeMB`
     (`maxGlobalDataSizeMB` / `maxGlobalRawDataSizeMB` apply)
   - `local`: `maxGlobalDataSizeMB`, `maxGlobalRawDataSizeMB` (SmartStore-only)
4. **Local limits** *(local)* — size limits per index vs. `volume:` `maxVolumeDataSizeMB`;
   indexes not on a volume; `homePath` / `coldPath` on the same volume as `thawedPath`.
5. **Mixed storage** — only when at least one index is `smartstore` and one is `local`.
6. **Cross-site differences** *(both)* — same index name on both sites with different storage
   mode, retention or limits. For `smartstore` also remote volume, bucket, endpoint,
   encryption, credentials fingerprint. One multisite cluster needs one definition (and one
   remote store) per index: migration item, never generated (🔴).
7. **Cache manager drift** *(smartstore)* — `[cachemanager]` differs between indexers / sites.
8. **Retention vs. policy** *(both)* — effective retention per index against a policy value
   supplied per environment (empty = report only).

Any retention change is 🔴: lowering `frozenTimePeriodInSecs` or a size limit deletes data
at the next freeze cycle, with no archive to recover from.

### SH searches, parser, rules, report — days 2–5

Day 2 searches for retention: `| rest splunk_server=* /services/data/indexes` (size,
minTime, maxTime, limits per peer) and `_internal` BucketMover freeze events per index.

See the week plan; specified in SPEC-002 before day 2 work starts.
