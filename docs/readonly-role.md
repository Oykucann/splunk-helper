# Read-only Splunk role for REST collection

Create on each search head (one per site). Do not reuse an admin or power-user token:
`shx-collect` refuses tokens with write/admin capabilities (SPEC-002).

`etc/apps/<your_admin_app>/local/authorize.conf`:

```ini
[role_shx_ro]
importRoles =
search = enabled
rest_properties_get = enabled
srchIndexesAllowed = *;_*
srchIndexesDefault = main
srchJobsQuota = 2
rtSrchJobsQuota = 0
srchDiskQuota = 200
srchMaxTime = 600
```

- `srchIndexesAllowed = *;_*` is needed for `tstats` data presence and `_internal`/`_audit`.
- No `importRoles`: inheriting `user` would bring `schedule_search` and similar.
- Create a user with only this role, then a token for it (Settings → Tokens), with an expiry.

Verify before the first run:

```bash
SHX_TOKEN_SITE1=... python3 -m shx.collect environments/<env>.toml --check --rest-only
```

The check prints the token's roles and any privileged capabilities. If a later call
returns HTTP 403 (for example listing search peers), the error names the endpoint; grant
only the matching `list_*` / `rest_*` read capability.
