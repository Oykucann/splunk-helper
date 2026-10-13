"""Index list per site: where each index is defined, its storage/retention settings, and
(when the SH searches ran) its size and time range, with cross-site differences marked."""

from __future__ import annotations

from collections import defaultdict

from shx.rules.context import RunContext

SETTINGS = ("datatype", "homePath", "coldPath", "thawedPath", "remotePath", "frozenTimePeriodInSecs",
            "maxTotalDataSizeMB", "maxGlobalDataSizeMB", "maxDataSize", "coldToFrozenDir",
            "coldToFrozenScript", "repFactor")
STATS = ("size_mb", "events", "earliest", "latest")
SKIP_PREFIXES = ("volume:", "provider:", "provider-family:")
INDEXER_ROOTS = ("manager-apps", "master-apps", "peer-apps", "slave-apps")


def _skip(stanza: str) -> bool:
    return stanza == "default" or stanza.startswith(SKIP_PREFIXES)


def _raw_definitions(ctx: RunContext):
    """index -> site -> [(server, root/app/layer)]; and per-server raw entries for fallback."""
    defined = defaultdict(lambda: defaultdict(set))
    for snap in ctx.servers():
        for e in ctx.files(snap.name, conf="indexes"):
            if _skip(e.stanza):
                continue
            where = e.location.root if e.location.app is None else f"{e.location.root}/{e.location.app}"
            defined[e.stanza][snap.site or "no-site"].add(f"{snap.name}:{where}/{e.location.layer}")
    return defined


def _merge_raw(entries) -> dict[str, dict[str, str]]:
    """Splunk-like precedence for one server's app tree: all local before all default,
    apps in ASCII order; [default] stanza fills unset keys."""
    ordered = sorted(entries, key=lambda e: (e.location.layer != "local", e.location.app or ""))
    out = defaultdict(dict)
    defaults = {}
    for e in ordered:
        target = defaults if e.stanza == "default" else out[e.stanza]
        target.setdefault(e.key, e.value)
    return {st: {**defaults, **kv} for st, kv in out.items()}


def _effective_by_site(ctx: RunContext) -> dict[str, dict[str, dict[str, str]]]:
    """site -> index -> settings. Prefer an indexer's btool; else the CM's manager-apps."""
    by_site = {}
    for site in sorted({s.site or "no-site" for s in ctx.servers()}):
        idx = [s for s in ctx.servers("idx") if (s.site or "no-site") == site and ctx.has_btool(s.name, "indexes")]
        if idx:
            conf = ctx.effective(idx[0].name)["indexes"]
            default = {k: v.value for k, v in conf.get("default", {}).items()}
            by_site[site] = {st: {**default, **{k: v.value for k, v in kv.items()}}
                             for st, kv in conf.items() if not _skip(st)}
            continue
        cms = [s for s in ctx.servers("cm") if (s.site or "no-site") == site]
        if cms:
            entries = [e for e in ctx.files(cms[0].name, conf="indexes") if e.location.root in INDEXER_ROOTS]
            by_site[site] = {st: kv for st, kv in _merge_raw(entries).items() if not _skip(st)}
    return by_site


def _stats_by_site(ctx: RunContext) -> dict[str, dict[str, dict[str, str]]]:
    acc = defaultdict(lambda: defaultdict(lambda: {"size": 0.0, "events": 0.0, "min": None, "max": None}))
    for sh, row in ctx.search_rows("indexes"):
        site = ctx.rest_site(sh) or "no-site"
        a = acc[site][row.get("title", "")]
        for key, field in (("size", "currentDBSizeMB"), ("events", "totalEventCount")):
            try:
                a[key] += float(row.get(field) or 0)
            except ValueError:
                pass
        for key, field, pick in (("min", "minTime", min), ("max", "maxTime", max)):
            v = row.get(field)
            if v:
                a[key] = v if a[key] is None else pick(a[key], v)
    return {site: {i: {"size_mb": f"{a['size']:.0f}", "events": f"{a['events']:.0f}",
                       "earliest": a["min"] or "", "latest": a["max"] or ""} for i, a in idx.items()}
            for site, idx in acc.items()}


def indexes_table(ctx: RunContext) -> tuple[list[dict], list[str]]:
    defined = _raw_definitions(ctx)
    effective = _effective_by_site(ctx)
    stats = _stats_by_site(ctx)
    sites = sorted({s.site or "no-site" for s in ctx.servers()} | set(stats))
    names = set(defined) | {i for v in effective.values() for i in v} | {i for v in stats.values() for i in v}

    rows = []
    for index in sorted(n for n in names if n):
        row = {"index": index, "internal": "yes" if index.startswith("_") else ""}
        present = []
        for site in sites:
            eff = effective.get(site, {}).get(index)
            st = stats.get(site, {}).get(index)
            here = bool(eff or st or defined.get(index, {}).get(site))
            row[f"{site}:present"] = "yes" if here else ""
            if here:
                present.append(site)
            row[f"{site}:defined_in"] = "; ".join(sorted(defined.get(index, {}).get(site, ())))
            for key in SETTINGS:
                row[f"{site}:{key}"] = (eff or {}).get(key, "")
            for key in STATS:
                row[f"{site}:{key}"] = (st or {}).get(key, "")
        row["only_in"] = present[0] if len(present) == 1 and len(sites) > 1 else ""
        row["differs"] = ", ".join(k for k in SETTINGS if len(present) > 1
                                   and len({row[f"{s}:{k}"] for s in present}) > 1)
        rows.append(row)
    columns = ["index", "internal", "only_in", "differs"]
    for site in sites:
        columns += [f"{site}:present", f"{site}:defined_in"] + [f"{site}:{k}" for k in SETTINGS] + \
                   [f"{site}:{k}" for k in STATS]
    return rows, columns
