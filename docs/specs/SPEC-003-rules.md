# SPEC-003: Rules and findings (`shx-findings`)

## Model

A **Finding** has a rule id, title, severity (`high` / `medium` / `low` / `info`), confidence
(`proven` = configuration or log evidence; `suspected` = inferred), category, a target string,
servers, sites, evidence items (server, path:line, stanza, key, value, search, detail) and a
recommendation. Its id is `rule-sha256(target)[:10]`, stable across runs so two runs can be
diffed.

Every rule ends in one status: `ran`, `not_applicable` (nothing to check, e.g. no SmartStore),
`insufficient_data` (inputs not collected, e.g. no REST) or `error` (bug; other rules still run).
A rule that did not run is never reported as passed.

Rules read only `RunContext` (`src/shx/rules/context.py`): snapshots, effective btool config,
raw conf files with app/layer/line, REST search rows, and name resolution of hosts seen in logs
(env name, address, OS hostname, `serverName`).

## Catalog

| Rule | Checks | Evidence | Severity |
|---|---|---|---|
| HA-001 | Effective config differs inside an HA group | btool | high |
| HA-002 | App presence/version/content/local differs inside an HA group | manifest apps | high |
| HA-003 | Pull input (scripted, DB Connect, unknown modular) enabled on an HA member | btool inputs, db_inputs | high |
| HA-004 | DS serverclass with `restartSplunkd` matching 2+ members of one HA group | DS btool serverclass | high |
| FWD-001 | `tcpout` group with static `server` list, no indexer discovery | btool outputs | medium |
| FWD-002 | `useACK` off | btool outputs | medium |
| FWD-003 | No TLS settings on a `tcpout` group | btool outputs | low |
| DATA-001 | Index-time props for a sourcetype on SH/indexer/CM but not on the site's HFs | btool props (+ metrics) | high if the sourcetype is seen on an HF, else medium |
| DATA-002 | Same props/transforms stanza+key with different values in different apps | raw files | medium |
| DATA-003 | Same origin host via 2+ independent HFs/HA groups | `host_by_forwarder` | high across sites, else medium |
| INP-001 | Enabled scripted input, script missing | path checks + btool | high |
| INP-002 | Enabled monitor input, path missing | path checks + btool | medium |
| INP-003 | ExecProcessor ERRORs | `exec_errors` | medium |
| INP-004 | DB Connect runs not completed / server errors | `dbx_jobs`, `dbx_errors` | medium / low |
| INP-005 | Blocked queues | `blocked_queues` | high on HF |
| DS-001 | Client app not on DS; content differs from DS; client-only `local/` | manifest apps | medium / high for local |
| SHC-001 | SH apps with `local/`; private user objects | manifest | medium |
| XS-001 | `must_match` config differs between sites | conf comparison | high |
| SEC-001 | Cleartext secret (`<redacted:plain:…>`), HEC tokens excepted | raw files | high |
| SEC-002 | Suspected credential in a script | manifest | medium (suspected) |
| SEC-003 | `sslVerifyServerCert = false` set explicitly | btool | low |
| RET-001 | No archive and: freeze events (proven) / ≥90% of size cap / time limit < 6y | `indexes`, `freeze_events` | high / high / medium |
| RET-002 | ≥6y and no size limit (SmartStore) / no explicit limits (local) | `indexes` + raw | medium / low |
| RET-003 | Limit the storage mode ignores | raw indexes.conf | medium |
| RET-004 | SmartStore and local indexes mixed | `indexes` | low |
| RET-005 | Same index differs between sites (mode, limits, remotePath, archive) | `indexes` | high for mode/remotePath |

Retention rules are evaluated per index **and site** (sites are independent today). Index facts
come from the SH `indexes` search; without it, from indexer btool; without either the rules
report `insufficient_data`. Internal indexes (`_*`) are skipped.

## Not yet covered

Local volume limits vs. index sizes (SPEC-001 rule 4), cache-manager drift beyond the generic
config comparison, retention-vs-policy (needs a policy value per environment), and unused
knowledge objects from `scheduler_runs` / `dashboard_views` (day 4).

## Output

`reports/findings.json` (rules with status + findings), `findings.csv`, `findings.md`
(severity-ordered, evidence capped at 8 items per finding in Markdown).
