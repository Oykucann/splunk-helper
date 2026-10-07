"""Dead, broken and overloaded inputs."""

from __future__ import annotations

from collections import defaultdict

from shx.rules.base import Evidence, Finding, InsufficientData, NotApplicable, rule
from shx.rules.context import RunContext, is_true


def _input_disabled(ctx: RunContext, server: str, stanza: str) -> bool | None:
    """True/False from effective inputs; None when btool inputs was not collected."""
    inputs = ctx.effective(server).get("inputs")
    if inputs is None:
        return None
    kv = inputs.get(stanza)
    if kv is None:
        return True  # not in effective config: not active on this host
    d = kv.get("disabled")
    return is_true(d.value if d else None)


def _path_checks(ctx: RunContext, kind: str):
    if not ctx.servers():
        raise InsufficientData("no snapshots collected")
    return [(snap, c) for snap in ctx.servers() for c in snap.manifest.get("path_checks", [])
            if c["kind"] == kind]


@rule("INP-001", "Enabled scripted input whose script does not exist", "dead-input")
def missing_script(ctx: RunContext):
    for snap, c in _path_checks(ctx, "script"):
        if c["exists"]:
            continue
        disabled = _input_disabled(ctx, snap.name, c["stanza"])
        if disabled:
            continue
        yield Finding(
            "INP-001", f"Script missing for {c['stanza']} on {snap.name}",
            "high" if disabled is False else "medium", "proven" if disabled is False else "suspected",
            "dead-input", f"{snap.name} / {c['stanza']}", servers=[snap.name],
            sites=[snap.site] if snap.site else [],
            evidence=[Evidence(server=snap.name, path=c["conf"], stanza=c["stanza"],
                               detail=f"{c['checked_path']} does not exist")],
            recommendation="Remove or disable the input; it errors on every interval.")


@rule("INP-002", "Enabled monitor input on a path that does not exist", "dead-input")
def missing_monitor_path(ctx: RunContext):
    for snap, c in _path_checks(ctx, "monitor"):
        if c["exists"] or _input_disabled(ctx, snap.name, c["stanza"]):
            continue
        yield Finding(
            "INP-002", f"Monitored path missing for {c['stanza']} on {snap.name}", "medium", "proven",
            "dead-input", f"{snap.name} / {c['stanza']}", servers=[snap.name],
            sites=[snap.site] if snap.site else [],
            evidence=[Evidence(server=snap.name, path=c["conf"], stanza=c["stanza"],
                               detail=f"{c['checked_path']} does not exist"
                               + (" (wildcard prefix)" if c["wildcard"] else ""))],
            recommendation="Confirm the source moved or was retired, then remove the stanza.")


@rule("INP-003", "Scripted or modular input writing errors", "broken-input")
def exec_errors(ctx: RunContext):
    if not ctx.has_search("exec_errors"):
        raise InsufficientData("exec_errors search not collected")
    for sh, row in ctx.search_rows("exec_errors"):
        if row.get("log_level") != "ERROR":
            continue
        host, script = row.get("host", ""), row.get("script") or "(unparsed)"
        snap = ctx.resolve(host)
        yield Finding(
            "INP-003", f"{script} logs errors on {host}", "medium", "proven", "broken-input",
            f"{host} / {script}", servers=[snap.name if snap else host],
            sites=[ctx.rest_site(sh)] if ctx.rest_site(sh) else [],
            evidence=[Evidence(server=host, search="exec_errors",
                               detail=f"{row.get('count')} errors, last {row.get('last_seen')}: "
                                      f"{(row.get('sample') or '')[:300]}")],
            recommendation="Fix or disable the script; check whether it still produces any data.")


@rule("INP-004", "DB Connect inputs failing", "broken-input")
def dbx_failures(ctx: RunContext):
    if not (ctx.has_search("dbx_jobs") or ctx.has_search("dbx_errors")):
        raise InsufficientData("DB Connect searches not collected")
    for sh, row in ctx.search_rows("dbx_jobs"):
        failed = int(float(row.get("not_completed") or 0))
        if not failed:
            continue
        yield Finding(
            "INP-004", f"DB input {row.get('input_name')} failed {failed} times on {row.get('host')}",
            "medium", "proven", "broken-input", f"{row.get('host')} / {row.get('input_name')}",
            servers=[row.get("host", "")],
            evidence=[Evidence(server=row.get("host"), search="dbx_jobs",
                               detail=f"runs {row.get('runs')}, last status {row.get('last_status')}")],
            recommendation="Check the connection/identity; a failing rising-column input may skip data.")
    for sh, row in ctx.search_rows("dbx_errors"):
        yield Finding(
            "INP-004", f"DB Connect server errors on {row.get('host')}", "low", "proven", "broken-input",
            f"{row.get('host')} / {row.get('sourcetype')}", servers=[row.get("host", "")],
            evidence=[Evidence(server=row.get("host"), search="dbx_errors", detail=f"{row.get('count')} errors")],
            recommendation="Review splunk_app_db_connect logs.")


@rule("INP-005", "Blocked pipeline queues", "capacity")
def blocked_queues(ctx: RunContext):
    if not ctx.has_search("blocked_queues"):
        raise InsufficientData("blocked_queues search not collected")
    by_host = defaultdict(list)
    for _sh, row in ctx.search_rows("blocked_queues"):
        by_host[row.get("host", "")].append(row)
    if not by_host:
        raise NotApplicable("no blocked queues in the window")
    for host, rows in sorted(by_host.items()):
        snap = ctx.resolve(host)
        total = sum(int(float(r.get("count") or 0)) for r in rows)
        yield Finding(
            "INP-005", f"{host} has blocked queues", "high" if snap and snap.role == "hf" else "medium",
            "proven", "capacity", f"{host} / queues", servers=[snap.name if snap else host],
            evidence=[Evidence(server=host, search="blocked_queues",
                               detail=f"{r.get('name')}: {r.get('count')}") for r in rows],
            recommendation=f"{total} blocked samples in 7 days. On an HF this delays every source behind "
                           "it; check the slowest downstream queue first.")
