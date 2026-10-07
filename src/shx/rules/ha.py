"""HA-group and forwarding rules: things that break failover or the multisite target."""

from __future__ import annotations

import fnmatch
from collections import defaultdict

from shx.conf.compare import compare_all as compare_confs
from shx.conf.inputs import app_of_source, is_pull_stanza, scheme
from shx.inventory.apps import compare_ha_groups
from shx.rules.base import Evidence, Finding, InsufficientData, NotApplicable, rule
from shx.rules.context import RunContext, is_true



def _require_ha(ctx: RunContext):
    groups = {g: m for g, m in ctx.ha_groups.items() if len(m) > 1}
    if not groups:
        raise NotApplicable("no HA group with two or more collected members")
    return groups


@rule("HA-001", "HA group members have different configuration", "prod-risk")
def ha_config_drift(ctx: RunContext):
    _require_ha(ctx)
    grouped = defaultdict(list)
    for d in compare_confs(ctx.snapshots):
        if d.level == "ha_group":
            grouped[(d.scope, d.conf, d.stanza)].append(d)
    for (group, conf, stanza), diffs in sorted(grouped.items()):
        servers = sorted({m for d in diffs for m in d.values})
        yield Finding(
            "HA-001", f"{conf}.conf [{stanza}] differs inside HA group {group}", "high", "proven",
            "prod-risk", f"{group} / {conf} / {stanza}", servers=servers,
            evidence=[Evidence(server=m, stanza=stanza, key=d.key, value=v, detail=f"{conf}.conf")
                      for d in diffs for m, v in d.values.items()],
            recommendation="Make every member identical (same apps from the same serverclass). "
                           "After a failover the other node parses and routes data differently.")


@rule("HA-002", "HA group members have different apps", "prod-risk")
def ha_app_drift(ctx: RunContext):
    _require_ha(ctx)
    for d in compare_ha_groups(ctx.snapshots):
        yield Finding(
            "HA-002", f"App {d.app} ({d.kind}) differs inside HA group {d.scope}", "high", "proven",
            "prod-risk", f"{d.scope} / {d.root} / {d.app} / {d.kind}", servers=sorted(d.values),
            evidence=[Evidence(server=m, detail=f"{d.root}/{d.app}: {d.kind} = {v}") for m, v in d.values.items()],
            recommendation="Deploy the same app version and content to every member from the DS.")


def _enabled(kv) -> bool:
    d = kv.get("disabled")
    return not is_true(d.value if d else None)


def _source(kv) -> str | None:
    return next(iter(kv.values())).source if kv else None


def _pull_inputs(ctx: RunContext, snap) -> dict[str, tuple[str, str | None]]:
    """Enabled pull inputs on a server: key -> (kind, source file)."""
    eff = ctx.effective(snap.name)
    out = {}
    for stanza, kv in eff.get("inputs", {}).items():
        if is_pull_stanza(stanza) and _enabled(kv):
            out[stanza] = (scheme(stanza), _source(kv))
    for stanza, kv in eff.get("db_inputs", {}).items():
        if stanza != "default" and _enabled(kv):
            out[f"db_inputs://{stanza}"] = ("db_input", _source(kv))
    return out


@rule("HA-003", "Pull inputs on an HA group", "prod-risk")
def pull_inputs_on_ha(ctx: RunContext):
    groups = _require_ha(ctx)
    for group, members in sorted(groups.items()):
        per_member = {m.name: _pull_inputs(ctx, m) for m in members if ctx.has_btool(m.name, "inputs")}
        running_on = {}
        for name, inputs in per_member.items():
            for key in inputs:
                running_on.setdefault(key, []).append(name)
        colocated = {}
        for key, names in sorted(running_on.items()):
            kind, source = per_member[names[0]][key]
            if len(names) > 1:
                yield Finding(
                    "HA-003", f"{kind} input runs on {len(names)} members of {group}", "high",
                    "proven", "prod-risk", f"{group} / {key}", servers=sorted(names),
                    evidence=[Evidence(server=n, path=per_member[n][key][1], stanza=key) for n in sorted(names)],
                    recommendation="A pull input on several nodes fetches the same data on each: duplicates. "
                                   "Keep it on one node (or the dedicated pull HF).")
                continue
            snap = ctx.by_name[names[0]]
            if snap.pull_apps and app_of_source(source or "") in snap.pull_apps:
                colocated.setdefault(snap.name, []).append((key, source))
                continue
            yield Finding(
                "HA-003", f"Unexpected {kind} input on HA member {snap.name}", "high",
                "proven" if kind in ("script", "db_input") else "suspected", "prod-risk",
                f"{snap.name} / {key}", servers=[snap.name], sites=[snap.site] if snap.site else [],
                evidence=[Evidence(server=snap.name, path=source, stanza=key)],
                recommendation="Not declared as a pull role for this node (pull_apps). Move it to the "
                               "pull HF, or declare the app if co-locating it here is intended.")
        for name, items in sorted(colocated.items()):
            snap = ctx.by_name[name]
            yield Finding(
                "HA-003", f"{name} runs {len(items)} pull inputs alongside {group} (declared)", "low",
                "proven", "prod-risk", f"{group} / {name} / colocated-pull", servers=[name],
                sites=[snap.site] if snap.site else [],
                evidence=[Evidence(server=name, path=src, stanza=key) for key, src in items],
                recommendation="Intended: pull inputs use the node's own address, so VIP moves do not "
                               "affect them. They have no failover if this node is down, and pause when "
                               "it restarts (e.g. a restartSplunkd serverclass). Accept, or move them to "
                               "a dedicated pull HF in the target design.")


def _class_members(classes: dict, cls: str, hf_names: dict[str, set[str]]) -> set[str]:
    kv = classes.get(f"serverClass:{cls}", {})
    white = [v.value for k, v in kv.items() if k.startswith("whitelist.")]
    black = [v.value for k, v in kv.items() if k.startswith("blacklist.")]
    members = set()
    for server, names in hf_names.items():
        def hit(patterns):
            return any(fnmatch.fnmatch(n, p.lower()) for p in patterns for n in names)
        if hit(white) and not hit(black):
            members.add(server)
    return members


@rule("HA-004", "Serverclass restarts every member of an HA group at once", "prod-risk")
def serverclass_restarts_ha(ctx: RunContext):
    groups = _require_ha(ctx)
    ds_list = [s for s in ctx.servers("ds") if ctx.has_btool(s.name, "serverclass")]
    if not ds_list:
        raise InsufficientData("no deployment server with btool serverclass collected")
    for ds in ds_list:
        classes = ctx.effective(ds.name)["serverclass"]
        hf_names = {s.name: ctx.aliases(s) for s in ctx.servers("hf")}
        global_restart = classes.get("global", {}).get("restartSplunkd")
        for stanza in sorted(classes):
            parts = stanza.split(":")
            if parts[0] != "serverClass" or len(parts) not in (2, 4):
                continue
            cls = parts[1]
            members = _class_members(classes, cls, hf_names)
            app = parts[3] if len(parts) == 4 else None
            own = classes[stanza].get("restartSplunkd")
            parent = classes.get(f"serverClass:{cls}", {}).get("restartSplunkd")
            restart = (own or parent or global_restart)
            if len(parts) == 2 or not is_true(restart.value if restart else None):
                continue
            for group, gmembers in sorted(groups.items()):
                hit = sorted(members & {m.name for m in gmembers})
                if len(hit) >= 2:
                    yield Finding(
                        "HA-004", f"Serverclass {cls} restarts all of {group} for app {app}", "high",
                        "proven", "prod-risk", f"{ds.name} / {cls} / {app} / {group}",
                        servers=hit, sites=sorted({m.site for m in gmembers if m.site}),
                        evidence=[Evidence(server=ds.name, stanza=stanza, key="restartSplunkd",
                                           value=restart.value, detail=f"matches {', '.join(hit)}")],
                        recommendation=f"Split {group} into A/B serverclasses so a change restarts one "
                                       "node, is verified, then the other.")


def _tcpout_groups(eff):
    outputs = eff.get("outputs", {})
    return {s: kv for s, kv in outputs.items() if s.startswith("tcpout:")}, outputs


@rule("FWD-001", "Forwarder uses a static indexer list", "target-readiness")
def static_indexer_list(ctx: RunContext):
    hfs = [s for s in ctx.servers("hf") if ctx.has_btool(s.name, "outputs")]
    if not hfs:
        raise InsufficientData("no HF outputs collected")
    for s in hfs:
        groups, _ = _tcpout_groups(ctx.effective(s.name))
        for g, kv in sorted(groups.items()):
            if "server" in kv and "indexerDiscovery" not in kv:
                yield Finding(
                    "FWD-001", f"{s.name} sends to a static indexer list ({g})", "medium", "proven",
                    "target-readiness", f"{s.name} / {g}", servers=[s.name], sites=[s.site] if s.site else [],
                    evidence=[Evidence(server=s.name, path=kv["server"].source, stanza=g, key="server",
                                       value=kv["server"].value)],
                    recommendation="Use indexer discovery against the cluster manager, with the HF's "
                                   "site set for site affinity. Changing outputs is a manual 🔴 step.")


@rule("FWD-002", "Forwarder without indexer acknowledgement", "data-integrity")
def no_use_ack(ctx: RunContext):
    hfs = [s for s in ctx.servers("hf") if ctx.has_btool(s.name, "outputs")]
    if not hfs:
        raise InsufficientData("no HF outputs collected")
    for s in hfs:
        groups, outputs = _tcpout_groups(ctx.effective(s.name))
        base = outputs.get("tcpout", {}).get("useACK")
        for g, kv in sorted(groups.items()):
            ack = kv.get("useACK") or base
            if not is_true(ack.value if ack else None):
                yield Finding(
                    "FWD-002", f"{s.name} {g} has useACK off", "medium", "proven", "data-integrity",
                    f"{s.name} / {g}", servers=[s.name],
                    evidence=[Evidence(server=s.name, stanza=g, key="useACK",
                                       value=ack.value if ack else "(default false)")],
                    recommendation="Enable useACK so data in flight survives an indexer restart.")


@rule("FWD-003", "Forwarder sends without TLS", "security")
def no_tls(ctx: RunContext):
    hfs = [s for s in ctx.servers("hf") if ctx.has_btool(s.name, "outputs")]
    if not hfs:
        raise InsufficientData("no HF outputs collected")
    tls_keys = {"clientCert", "sslCertPath", "sslRootCAPath", "useSSL", "sslPassword"}
    for s in hfs:
        groups, outputs = _tcpout_groups(ctx.effective(s.name))
        base = outputs.get("tcpout", {})
        for g, kv in sorted(groups.items()):
            merged = {**base, **kv}
            use_ssl = merged.get("useSSL")
            if (use_ssl and not is_true(use_ssl.value) and use_ssl.value.lower() != "auto") or \
                    not (tls_keys & set(merged)):
                yield Finding(
                    "FWD-003", f"{s.name} {g} forwards without TLS", "low", "proven", "security",
                    f"{s.name} / {g}", servers=[s.name],
                    evidence=[Evidence(server=s.name, stanza=g, detail="no TLS settings in effective outputs")],
                    recommendation="Enable TLS between forwarders and indexers.")
