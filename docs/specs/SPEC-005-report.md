# SPEC-005: Decision report (`shx-report`)

## Why

The rule/severity outputs (`shx-compare`, `shx-findings`) made judgements the environment
does not support (e.g. assuming secrets must be shared). The engineer needs three plain views
to decide the cleanup, with no verdicts:

1. The same app on SH, CM, DS (→ HF/UF) and HFs with different versions or settings.
2. Instance-level settings (server.conf, web.conf, …): what is non-stock, where, from which file.
3. Indexes per site, to see site-specific differences.

## Outputs (CSV, `reports/`)

| File | Rows | Columns |
|---|---|---|
| `apps.csv` | one per app | locations, variants, versions, with_local, vendor_local_only, then one per location `site/server/root` with `version letter [+local] [disabled]` (same letter = same version and shipped content) |
| `app_settings.csv` | apps with more than one variant or differing `local/`: one per conf/stanza/key (or file) whose value differs | each location's value (`[local]` when from local/, `(unset)`, `(missing)` for files); `scope` notes vendor apps where only local/ was collected |
| `system_settings.csv` | one per conf/stanza/key that is non-stock on at least one server, plus instance facts | `differs`, each server's effective value (`(not collected)` when that conf has no btool), `sources` (system/local or app) |
| `indexes.csv` | one per index | `only_in`, `differs` (settings that differ between sites), then per site: present, defined_in (server:root/app/layer), settings, size_mb, events, earliest, latest |
| `report.md` | — | counts and the top differences of the three views |

Locations: `apps`, `peer-apps`, `slave-apps`, `manager-apps` (CM → indexers), `master-apps`,
`shcluster/apps` (deployer), `deployment-apps` (DS → HF/UF; UFs are not collected, the DS copy
stands for them).

System confs: server, web, outputs, deploymentclient, distsearch, authentication, authorize,
limits, health, alert_actions, and inputs.conf `[default]`, `[http]`, `[SSL]`, `[splunktcp]`.

Index settings per site come from an indexer's btool when collected, else from the CM's
`manager-apps` merged Splunk-style (local before default, apps in ASCII order, `[default]`
fills); sizes and time ranges from the SH `indexes` search summed per site.

Secrets are never judged: each row labels equal fingerprints `secret#1`, `secret#2`, … with
`(enc)` / `(plain)`.

## Non-goals

No generated apps, packages or config files; nothing is written to servers. Choosing the target
version/value is the engineer's decision based on these tables.
