"""Index storage and retention rules (SPEC-001 "Index storage and retention").

Storage mode is decided per index: `smartstore` when remotePath is set, else `local`.
Facts come from the SH `indexes` REST search (effective values per indexer); when that is
missing, from indexer btool. Explicitly set keys come from the raw indexes.conf files.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from shx.rules.base import Evidence, Finding, InsufficientData, NotApplicable, rule
from shx.rules.context import RunContext

DEFAULT_FROZEN_SECS = 188697600          # 6 years
DEFAULT_MAX_TOTAL_MB = 500000            # local indexes only
NEAR_CAP = 0.9
LOCAL_ONLY_LIMITS = ("maxTotalDataSizeMB", "homePath.maxDataSizeMB", "coldPath.maxDataSizeMB")
SMARTSTORE_ONLY_LIMITS = ("maxGlobalDataSizeMB", "maxGlobalRawDataSizeMB")
SKIP_STANZAS = ("default", "provider-family:", "provider:", "volume:")


@dataclass
class IndexFact:
    index: str
    server: str
    site: str | None
    values: dict[str, str] = field(default_factory=dict)
    source: str = "rest"

    def get(self, key: str) -> str:
        return (self.values.get(key) or "").strip()

    def num(self, key: str, default: float | None = None) -> float | None:
        try:
            return float(self.get(key))
        except ValueError:
            return default

    @property
    def mode(self) -> str:
        return "smartstore" if self.get("remotePath") else "local"

    @property
    def archived(self) -> bool:
        return bool(self.get("coldToFrozenDir") or self.get("coldToFrozenScript"))

    @property
    def internal(self) -> bool:
        return self.index.startswith("_") or self.index in ("history", "splunklogger")


def index_facts(ctx: RunContext) -> list[IndexFact]:
    facts = []
    for sh, row in ctx.search_rows("indexes"):
        if row.get("title") and str(row.get("disabled", "0")).lower() not in ("1", "true"):
            facts.append(IndexFact(row["title"], row.get("splunk_server", sh), ctx.rest_site(sh),
                                   {k: str(v) for k, v in row.items()}))
    if facts:
        return facts
    for snap in ctx.servers("idx"):
        conf = ctx.effective(snap.name).get("indexes", {})
        default = {k: s.value for k, s in conf.get("default", {}).items()}
        for stanza, kv in conf.items():
            if stanza.startswith(SKIP_STANZAS):
                continue
            values = {**default, **{k: s.value for k, s in kv.items()}}
            if values.get("disabled", "").lower() in ("1", "true"):
                continue
            facts.append(IndexFact(stanza, snap.name, snap.site, values, source="btool"))
    if not facts:
        raise InsufficientData("neither the SH indexes search nor indexer btool was collected")
    return facts


def explicit_keys(ctx: RunContext) -> dict[str, dict[str, list]]:
    """index -> key -> [(server, path, line, value)] from raw indexes.conf (incl. [default])."""
    out = defaultdict(lambda: defaultdict(list))
    for snap in ctx.servers():
        for e in ctx.files(snap.name, conf="indexes"):
            out[e.stanza][e.key].append((snap.name, e.path, e.line, e.value))
    return out


def freezes(ctx: RunContext) -> dict[str, list[dict]]:
    out = defaultdict(list)
    for _sh, row in ctx.search_rows("freeze_events"):
        if row.get("index_dir"):
            out[row["index_dir"]].append(row)
    return out


def _by_index(facts: list[IndexFact]) -> dict[str, list[IndexFact]]:
    out = defaultdict(list)
    for f in facts:
        out[f.index].append(f)
    return out


def _by_index_site(facts: list[IndexFact]) -> dict[tuple[str, str], list[IndexFact]]:
    """Sites are independent today, so the same index name is judged per site."""
    out = defaultdict(list)
    for f in facts:
        out[(f.index, f.site or "")].append(f)
    return out


def _target(index: str, site: str, what: str) -> str:
    return f"{index} / {site} / {what}" if site else f"{index} / {what}"


def _explicit_for(explicit, ctx: RunContext, index: str, key: str, site: str) -> list:
    rows = explicit.get(index, {}).get(key, []) + explicit.get("default", {}).get(key, [])
    return [r for r in rows if not site or ctx.by_name[r[0]].site in (site, None)]


@rule("RET-001", "Data deleted at freeze with no archive", "retention")
def deletion_without_archive(ctx: RunContext):
    facts = index_facts(ctx)
    frozen = freezes(ctx)
    for (index, site), fs in sorted(_by_index_site(facts).items()):
        if fs[0].internal or any(f.archived for f in fs):
            continue
        f = fs[0]
        secs = f.num("frozenTimePeriodInSecs", DEFAULT_FROZEN_SECS)
        size = max((x.num("currentDBSizeMB", 0) or 0) for x in fs)
        cap = f.num("maxTotalDataSizeMB", DEFAULT_MAX_TOTAL_MB) if f.mode == "local" else \
            (f.num("maxGlobalDataSizeMB", 0) or None)
        evidence = [Evidence(server=x.server, detail=f"{x.mode}, frozenTimePeriodInSecs={x.get('frozenTimePeriodInSecs') or 'default'}, "
                                                     f"size={x.get('currentDBSizeMB') or '?'} MB, cap={cap or 'none'} MB")
                    for x in fs]
        site_hosts = {x.server.lower() for x in fs}
        rows = [r for r in frozen.get(index, []) if not site or r.get("host", "").lower() in site_hosts]
        if rows:
            yield Finding(
                "RET-001", f"Index {index}: buckets are being deleted (no frozen archive)", "high", "proven",
                "retention", _target(index, site, "deleting"), servers=sorted({r.get('host', '') for r in rows}),
                sites=sorted({x.site for x in fs if x.site}),
                evidence=evidence + [Evidence(server=r.get("host"), search="freeze_events",
                                              detail=f"{r.get('freezes')} buckets frozen, last {r.get('last_freeze')}")
                                     for r in rows],
                recommendation="Confirm this matches the retention policy. If data must be kept, add "
                               "coldToFrozenDir/Script before anything else (manual 🔴 change).")
        elif cap and f.mode == "local" and size >= NEAR_CAP * cap:
            yield Finding(
                "RET-001", f"Index {index} is at {int(100 * size / cap)}% of its size cap; oldest data will be deleted",
                "high", "suspected", "retention", _target(index, site, "near-cap"), sites=[site] if site else [],
                evidence=evidence,
                recommendation="The 500 GB default applies when maxTotalDataSizeMB is not set. Decide "
                               "retention explicitly; add an archive if data must be kept.")
        elif secs < DEFAULT_FROZEN_SECS:
            yield Finding(
                "RET-001", f"Index {index} deletes data after {int(secs // 86400)} days (no archive)", "medium",
                "suspected", "retention", _target(index, site, "time-limit"), sites=[site] if site else [],
                evidence=evidence, recommendation="Confirm against policy; nothing is kept after this age.")


@rule("RET-002", "Index retention is effectively unbounded", "retention")
def unbounded_growth(ctx: RunContext):
    explicit = explicit_keys(ctx)
    for (index, site), fs in sorted(_by_index_site(index_facts(ctx)).items()):
        f = fs[0]
        if f.internal or f.num("frozenTimePeriodInSecs", DEFAULT_FROZEN_SECS) < DEFAULT_FROZEN_SECS:
            continue
        if f.mode == "smartstore" and not f.num("maxGlobalDataSizeMB", 0):
            sev, why = "medium", "no time limit and maxGlobalDataSizeMB = 0: remote store grows without bound"
        elif f.mode == "local" and not _explicit_for(explicit, ctx, index, "maxTotalDataSizeMB", site):
            sev, why = "low", "no explicit limits: only the 6-year and 500 GB defaults apply"
        else:
            continue
        yield Finding(
            "RET-002", f"Index {index}{' (' + site + ')' if site else ''}: {why}", sev, "proven", "retention",
            _target(index, site, "unbounded"), sites=[site] if site else [],
            evidence=[Evidence(server=x.server, detail=f"{x.mode}, oldest event {x.get('minTime') or '?'}, "
                                                       f"size {x.get('currentDBSizeMB') or '?'} MB") for x in fs],
            recommendation="Set frozenTimePeriodInSecs (and a size limit) from the retention policy. "
                           "Lowering them deletes data at the next freeze: plan it as a 🔴 change.")


@rule("RET-003", "Retention limit that the index's storage mode ignores", "retention")
def ineffective_limit(ctx: RunContext):
    explicit = explicit_keys(ctx)
    for (index, site), fs in sorted(_by_index_site(index_facts(ctx)).items()):
        mode = fs[0].mode
        ignored = LOCAL_ONLY_LIMITS if mode == "smartstore" else SMARTSTORE_ONLY_LIMITS
        for key in ignored:
            for server, path, line, value in explicit.get(index, {}).get(key, []):
                if site and ctx.by_name[server].site not in (site, None):
                    continue
                if mode == "local" and value.strip() in ("0", ""):
                    continue
                yield Finding(
                    "RET-003", f"Index {index} ({mode}): {key} has no effect", "medium", "proven", "retention",
                    _target(index, site, key), servers=[server], sites=[site] if site else [],
                    evidence=[Evidence(server=server, path=path, line=line, stanza=index, key=key, value=value)],
                    recommendation="Use maxGlobalDataSizeMB / maxGlobalRawDataSizeMB for SmartStore and "
                                   "maxTotalDataSizeMB / *.maxDataSizeMB for local indexes.")


@rule("RET-004", "Mixed SmartStore and local indexes", "retention")
def mixed_storage(ctx: RunContext):
    by_mode = defaultdict(set)
    for f in index_facts(ctx):
        if not f.internal:
            by_mode[f.mode].add(f.index)
    if "smartstore" not in by_mode:
        raise NotApplicable("no SmartStore index")
    if "local" not in by_mode:
        return
    yield Finding(
        "RET-004", f"{len(by_mode['local'])} indexes on local disk, {len(by_mode['smartstore'])} on SmartStore",
        "low", "proven", "retention", "storage / mixed",
        evidence=[Evidence(detail=f"local: {', '.join(sorted(by_mode['local'])[:40])}")],
        recommendation="Decide per index whether it moves to SmartStore in the target cluster.")


@rule("RET-005", "Same index defined differently on the two sites", "target-readiness")
def cross_site_index(ctx: RunContext):
    facts = index_facts(ctx)
    sites = {f.site for f in facts if f.site}
    if len(sites) < 2:
        raise NotApplicable("index facts from fewer than two sites")
    keys = ("frozenTimePeriodInSecs", "maxTotalDataSizeMB", "maxGlobalDataSizeMB", "remotePath",
            "coldToFrozenDir", "coldToFrozenScript", "datatype")
    for index, fs in sorted(_by_index(facts).items()):
        per_site = defaultdict(lambda: defaultdict(set))
        for f in fs:
            if f.site:
                per_site[f.site]["mode"].add(f.mode)
                for k in keys:
                    per_site[f.site][k].add(f.get(k))
        if len(per_site) < 2:
            continue
        diffs = [k for k in ("mode", *keys) if len({frozenset(v[k]) for v in per_site.values()}) > 1]
        if not diffs:
            continue
        yield Finding(
            "RET-005", f"Index {index} differs between sites: {', '.join(diffs)}",
            "high" if "mode" in diffs or "remotePath" in diffs else "medium", "proven", "target-readiness",
            f"{index} / cross-site", sites=sorted(per_site),
            evidence=[Evidence(detail=f"{site}: {k} = {', '.join(sorted(v[k])) or '(unset)'}")
                      for site, v in sorted(per_site.items()) for k in diffs],
            recommendation="One multisite cluster has one definition (and one remote store) per index. "
                           "Merging the data is a migration item, never generated (🔴).")
