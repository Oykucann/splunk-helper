# splunk-helper

Reads Splunk servers over SSH, **read-only**, and produces one simple HTML report:

- **Servers and Splunk service**: whether Splunk is installed, Enterprise or Universal
  Forwarder, version, running or not, systemd/init.d service, and service and process limits.
- **Apps**: every app on every server, its version, and whether the copies are identical.
- **App differences**: for apps whose copies differ, which conf/stanza/key (or file) differs,
  with each server's value and a short note.
- **Splunkbase**: the latest release and a link for apps found on Splunkbase, marked when newer.
- **Server settings (btool)**: non-default settings in server, web, outputs, deploymentclient,
  distsearch, limits, authentication, authorize, health and alert_actions, with differing rows
  highlighted.

## No files are copied, nothing is left on the servers

Collection runs in two phases. Both stream one script over SSH to stdin, run it as
`python3 -B -` (Splunk's `splunk cmd python3`, or the host `python3` on universal forwarders),
and get one JSON document back on stdout:

1. **Summary**, from every server: app names, versions and two fingerprints per app (shipped
   content and `local/`), the Splunk service, and `btool` for the instance-level confs only.
   No app file and no app setting leaves the server.
2. **Detail**, only from servers that hold an app whose copies differ: the masked conf values
   of those apps. For Splunk's own apps and vendor apps such as ES, only `local/` is read.

Splunk's own apps are recognised from the installation's `*-manifest` file, so the list follows
the installed version. The script only reads files and runs `splunk btool … list`. It installs
nothing, writes no file (no tar, no `.pyc`) and changes nothing. Secrets are masked before they
leave the server. Tests enforce this
(`tests/test_remote_guard.py`, `tests/test_remote_collect.py::test_writes_nothing_on_target`).
Only the OS and Splunk logs record that an SSH/sudo session or a Splunk CLI command ran.

Details: [ADR-0001](docs/adr/ADR-0001-read-only-collection.md).

## Requirements

- Python 3.9+ on your machine; no extra packages.
- SSH to each server with a key (default) or a password (`ssh_auth = "password"`), and
  passwordless `sudo -n -u splunk`. Alternatively, connect as the Splunk user and set
  `run_as = ""`.
- Internet from your machine for the Splunkbase lookup (only app names are sent), or `--offline`.

## Use

```bash
cp environments/example.toml environments/<env>.toml   # gitignored
export PYTHONPATH=src

python3 -m shx.collect environments/<env>.toml --dry-run   # what would run
python3 -m shx.collect environments/<env>.toml --check     # access check, collects nothing
python3 -m shx.collect environments/<env>.toml             # collect; prints the run directory

python3 -m shx.report.cli snapshots/<env>/<run_id>        # writes snapshots/<env>/<run_id>/report.html
```

You can regenerate the report from an existing run at any time. Add `--offline` to skip
Splunkbase, or `--env environments/<env>.toml` to relabel roles and sites without recollecting.

## Environment file

| Field | Meaning |
|---|---|
| `name`, `vips` | Environment name (snapshot folder) and the VIPs that must never be targeted |
| `exclude_apps` | App name patterns to leave out entirely, e.g. `["*dac_sync"]`: no detail collected, not in the report, their settings hidden from btool |
| `[[servers]]` `name`, `host`, `role`, `site` | `role`: `sh`, `cm`, `ds`, `deployer`, `idx`, `hf`, `uf` |
| `ha_group` | keepalived/haproxy members; collected last, one at a time |
| `also_roles` | Extra roles on one instance (e.g. a lab SH that is also the CM) |
| `ssh_user`, `ssh_auth`, `ssh_key`, `ssh_options`, `run_as` | How to log in |
| `splunk_home` | Default `/data/splunk`; e.g. `/opt/splunkforwarder` for UFs |
| `python` | `splunk` (default) or `system` (default for `uf`) |
| `local_only_apps` | Extra vendor apps to compare by `local/` only (ES and Splunk's own apps already are) |

Example: [environments/example.toml](environments/example.toml).

## Development

```bash
python3 -m pytest -q
```

The remote script (`src/shx/remote/collect_remote.py`) must stay standard-library only and
Python 3.6-compatible, because UF hosts may only have the OS Python.
