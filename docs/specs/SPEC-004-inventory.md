# SPEC-004: Inventory first (`shx-inventory`)

## Why

The engineer does not know in advance which apps and inputs each server carries, which HFs
are keepalived pairs, or which node also runs DB Connect / scripted inputs. Those facts feed
`ha_group`, `vips` and `pull_apps`, so they must come out of the first collection.

## Workflow

1. Collect with only `name`, `host`, `role`, `site` per server (node addresses, never VIPs).
2. `shx-inventory <run_dir>` → `inventory.md`, `inputs.csv`, `apps.csv`, `suggested_env.toml`.
3. Review and copy the suggestions into `environments/<env>.toml`.
4. `shx-compare` / `shx-findings <run_dir> --env environments/<env>.toml`. The environment file
   overrides `role`, `site`, `ha_group`, `pull_apps` from `run.json`; no recollection.

## Input inventory

One row per input stanza per server, from effective btool `inputs` and `db_inputs`:
server, role, site, HA group, owning app, layer, kind, scheme, stanza, enabled, sourcetype,
index, interval, connection, mode, host, source, whether the path exists (path checks), source
file. Kinds: `push` (udp, tcp, splunktcp, http/HEC), `pull` (script, DB Connect, any other
modular/API input), `local` (monitor, batch, Windows inputs). Servers without btool inputs are
listed as unknown, not empty.

## Suggestions

- **HA groups**: servers whose keepalived `vrrp_instance` share a `virtual_ipaddress`. Name:
  `<site>-<instance name>`. A VIP seen on only one collected server is noted (peer missing from
  the environment). haproxy pools are not discoverable from Splunk hosts; declare them by hand.
- **vips**: every keepalived VIP found.
- **pull_apps**: per HA member (suggested or declared), the apps owning its enabled pull inputs.
- **Warnings**: the same pull stanza enabled on several members of one group (duplicates).

`suggested_env.toml` is valid TOML; per-server values sit under `[suggested."<server>"]`, which
the environment loader rejects if pasted unchanged.
