"""Deployment-server drift, SHC migration blockers, cross-site blockers and security hygiene."""

from __future__ import annotations

from collections import defaultdict

from shx.conf.compare import compare_all as compare_confs
from shx.rules.base import Evidence, Finding, InsufficientData, NotApplicable, rule
from shx.rules.context import RunContext, is_true

@rule("DS-001", "Deployment-server drift on clients", "drift")
def ds_drift(ctx: RunContext):
    ds_list = [s for s in ctx.servers("ds") if any(a["root"] == "deployment-apps" for a in s.apps)]
    if not ds_list:
        raise InsufficientData("no deployment server with deployment-apps collected")
    clients = [s for s in ctx.servers("hf") if ctx.has_btool(s.name, "deploymentclient")]
    if not clients:
        raise NotApplicable("no collected HF is a deployment client")
    for client in clients:
        candidates = [d for d in ds_list if d.site == client.site] or ds_list
        staged = {}
        for ds in candidates:
            staged.update({a["name"]: (ds, a) for a in ds.apps if a["root"] == "deployment-apps"})
        for app in client.apps:
            if app["root"] != "apps":
                continue
            if app["name"] not in staged:
                if app.get("local_only"):
                    continue  # built-ins and vendor apps are not DS-managed
                yield Finding(
                    "DS-001", f"{app['name']} on {client.name} is not on the deployment server",
                    "medium", "proven", "drift", f"{client.name} / {app['name']} / unmanaged",
                    servers=[client.name], sites=[client.site] if client.site else [],
                    evidence=[Evidence(server=client.name, path=app["path"], detail=f"version {app.get('version')}")],
                    recommendation="Manually installed: bring it under a serverclass or remove it.")
                continue
            ds, staged_app = staged[app["name"]]
            if staged_app.get("content_sha") and app.get("content_sha") and \
                    staged_app["content_sha"] != app["content_sha"]:
                yield Finding(
                    "DS-001", f"{app['name']} on {client.name} differs from the DS copy", "medium",
                    "proven", "drift", f"{client.name} / {app['name']} / content", servers=[client.name, ds.name],
                    evidence=[Evidence(server=client.name, path=app["path"], detail=f"version {app.get('version')}"),
                              Evidence(server=ds.name, path=staged_app["path"],
                                       detail=f"version {staged_app.get('version')}")],
                    recommendation="The client copy was changed by hand or is a stale deploy; the next "
                                   "DS push will overwrite it.")
            if app.get("local_sha") and app.get("local_sha") != staged_app.get("local_sha"):
                yield Finding(
                    "DS-001", f"{app['name']} on {client.name} has local changes not on the DS", "high",
                    "proven", "drift", f"{client.name} / {app['name']} / local", servers=[client.name],
                    evidence=[Evidence(server=client.name, path=app["path"] + "/local",
                                       detail=f"{app.get('local_files')} local files")],
                    recommendation="Copy the change into deployment-apps first: a redeploy replaces the "
                                   "app directory and these settings are lost.")


@rule("SHC-001", "Search head content that a deployer cannot manage", "shc-migration")
def sh_local_content(ctx: RunContext):
    shs = ctx.servers("sh")
    if not shs:
        raise NotApplicable("no search head collected")
    for sh in shs:
        apps = [a for a in sh.apps if a["root"] == "apps" and a.get("local_files")]
        if apps:
            yield Finding(
                "SHC-001", f"{sh.name}: {len(apps)} apps carry local/ configuration", "medium", "proven",
                "shc-migration", f"{sh.name} / local", servers=[sh.name], sites=[sh.site] if sh.site else [],
                evidence=[Evidence(server=sh.name, path=a["path"] + "/local",
                                   detail=f"{a['local_files']} files" + (" (ES/vendor)" if a.get("local_only") else ""))
                          for a in sorted(apps, key=lambda a: -a["local_files"])],
                recommendation="Deployer pushes default/ only and never removes members' local/. Merge "
                               "local into default (or a site-neutral config app) before building the SHC.")
        users = defaultdict(int)
        for f in sh.manifest.get("files", []):
            if f["root"] == "users" and f["kind"] == "conf":
                users[f["path"].split("/")[2]] += 1
        if users:
            yield Finding(
                "SHC-001", f"{sh.name}: private knowledge objects for {len(users)} users", "medium",
                "proven", "shc-migration", f"{sh.name} / users", servers=[sh.name],
                evidence=[Evidence(server=sh.name, path=f"etc/users/{u}", detail=f"{n} conf files")
                          for u, n in sorted(users.items(), key=lambda x: -x[1])[:50]],
                recommendation="User directories are replicated within an SHC but not merged across "
                               "sites; decide per user which site's objects survive.")


@rule("XS-001", "Settings that must match before the sites can be one cluster", "target-readiness")
def cross_site_blockers(ctx: RunContext):
    if len(ctx.sites) < 2:
        raise NotApplicable("only one site collected")
    grouped = defaultdict(list)
    for d in compare_confs(ctx.snapshots):
        if d.level == "cross_site" and d.expect == "must_match":
            grouped[(d.scope, d.conf, d.stanza)].append(d)
    for (role, conf, stanza), diffs in sorted(grouped.items()):
        yield Finding(
            "XS-001", f"{role}: {conf}.conf [{stanza}] differs between sites", "high", "proven",
            "target-readiness", f"{role} / {conf} / {stanza}", sites=sorted({s for d in diffs for s in d.values}),
            evidence=[Evidence(stanza=stanza, key=d.key, value=v, detail=f"{site}: {conf}.conf")
                      for d in diffs for site, v in d.values.items()],
            recommendation=diffs[0].note or "Align before joining the sites into one cluster.")


@rule("SEC-001", "Cleartext secrets in configuration", "security")
def cleartext_secrets(ctx: RunContext):
    for snap in ctx.servers():
        for e in ctx.files(snap.name):
            if not e.value.startswith("<redacted:plain"):
                continue
            if e.conf == "inputs" and e.stanza.startswith("http://") and e.key == "token":
                continue  # HEC tokens are stored in cleartext by design
            yield Finding(
                "SEC-001", f"Cleartext {e.key} in {e.path} on {snap.name}", "high", "proven", "security",
                f"{snap.name} / {e.path} / {e.stanza} / {e.key}", servers=[snap.name],
                evidence=[Evidence(server=snap.name, path=e.path, line=e.line, stanza=e.stanza, key=e.key)],
                recommendation="Splunk encrypts most of these on restart; a cleartext value in a "
                               "deployed app means every client stores it in clear. Use passwords.conf.")


@rule("SEC-002", "Possible secrets inside scripts", "security")
def script_secrets(ctx: RunContext):
    for snap in ctx.servers():
        for f in snap.manifest.get("files", []):
            if f.get("suspected_secrets"):
                yield Finding(
                    "SEC-002", f"Possible credential in {f['path']} on {snap.name}", "medium", "suspected",
                    "security", f"{snap.name} / {f['path']}", servers=[snap.name],
                    evidence=[Evidence(server=snap.name, path=f["path"], line=h["line"], key=h["key"])
                              for h in f["suspected_secrets"]],
                    recommendation="Move credentials to passwords.conf / the input's credential store.")


@rule("SEC-003", "TLS certificate verification disabled", "security")
def tls_verification_off(ctx: RunContext):
    for snap in ctx.servers():
        eff = ctx.effective(snap.name)
        checks = [("server", "sslConfig")] + [("outputs", s) for s in eff.get("outputs", {})]
        for conf, stanza in checks:
            kv = eff.get(conf, {}).get(stanza, {})
            v = kv.get("sslVerifyServerCert")
            if v is not None and not v.is_system_default and not is_true(v.value):
                yield Finding(
                    "SEC-003", f"{snap.name} {conf}.conf [{stanza}] does not verify certificates", "low",
                    "proven", "security", f"{snap.name} / {conf} / {stanza}", servers=[snap.name],
                    evidence=[Evidence(server=snap.name, path=v.source, stanza=stanza,
                                       key="sslVerifyServerCert", value=v.value)],
                    recommendation="Enable verification with a common CA before connecting the sites.")


@rule("TOPO-001", "Several Splunk roles on one instance", "topology")
def colocated_roles(ctx: RunContext):
    combined = [s for s in ctx.servers() if s.also_roles]
    if not combined:
        raise NotApplicable("every server has a single role")
    for s in combined:
        yield Finding(
            "TOPO-001", f"{s.name} runs {s.role_label} on one instance", "info", "proven", "topology",
            f"{s.name} / {s.role_label}", servers=[s.name], sites=[s.site] if s.site else [],
            evidence=[Evidence(server=s.name, detail=f"declared roles: {', '.join(s.roles)}")],
            recommendation="Findings for this server cover all its roles; comparisons group it under "
                           f"its primary role ({s.role}). Acceptable in a lab; the multisite target "
                           "needs a dedicated cluster manager.")
