"""Data-correctness rules: where parsing happens, conflicting definitions, duplicate collection."""

from __future__ import annotations

import re
from collections import defaultdict

from shx.rules.base import Evidence, Finding, InsufficientData, NotApplicable, rule
from shx.rules.context import RunContext

# props.conf keys applied at parse/index time, i.e. on the first full Splunk instance (the HF).
INDEX_TIME_KEYS = {
    "LINE_BREAKER", "LINE_BREAKER_LOOKBEHIND", "SHOULD_LINEMERGE", "BREAK_ONLY_BEFORE",
    "BREAK_ONLY_BEFORE_DATE", "MUST_BREAK_AFTER", "MUST_NOT_BREAK_AFTER", "MUST_NOT_BREAK_BEFORE",
    "MAX_EVENTS", "TRUNCATE", "TIME_PREFIX", "TIME_FORMAT", "MAX_TIMESTAMP_LOOKAHEAD", "TZ",
    "DATETIME_CONFIG", "MAX_DAYS_AGO", "MAX_DAYS_HENCE", "CHARSET", "NO_BINARY_CHECK",
    "ANNOTATE_PUNCT", "SEGMENTATION",
}
INDEX_TIME_PREFIXES = ("TRANSFORMS-", "SEDCMD-", "INGEST_EVAL", "RULESET-")


def is_index_time(key: str) -> bool:
    return key in INDEX_TIME_KEYS or key.startswith(INDEX_TIME_PREFIXES)


def _sourcetype_stanza(stanza: str) -> bool:
    return not stanza.startswith(("source::", "host::", "rule::", "delayedrule::")) and stanza != "default"


def _index_time_stanzas(ctx: RunContext, server: str) -> dict[str, dict[str, str]]:
    """Sourcetype stanza -> {index-time key: source file}, excluding stock system defaults."""
    out = defaultdict(dict)
    for stanza, kv in ctx.effective(server).get("props", {}).items():
        if not _sourcetype_stanza(stanza):
            continue
        for key, setting in kv.items():
            if is_index_time(key) and not setting.is_system_default:
                out[stanza][key] = setting.source
    return out


@rule("DATA-001", "Index-time settings missing on the heavy forwarders", "data-integrity")
def index_time_not_on_hf(ctx: RunContext):
    hfs = [s for s in ctx.servers("hf") if ctx.has_btool(s.name, "props")]
    others = [s for s in ctx.servers() if s.role in ("sh", "idx", "cm") and ctx.has_btool(s.name, "props")]
    if not hfs:
        raise InsufficientData("no HF props collected")
    if not others:
        raise InsufficientData("no SH/indexer/CM props collected to compare with")

    # Sourcetypes each HF actually processed (from _internal metrics), when REST was collected.
    seen_on_hf = defaultdict(set)
    for _sh, row in ctx.search_rows("sourcetype_by_forwarder"):
        snap = ctx.resolve(row.get("host", ""))
        if snap and snap.role == "hf":
            seen_on_hf[row.get("series", "")].add(snap.name)

    for site in sorted({s.site for s in hfs}, key=str):
        site_hfs = [s for s in hfs if s.site == site]
        hf_keys = defaultdict(set)
        for hf in site_hfs:
            for stanza, keys in _index_time_stanzas(ctx, hf.name).items():
                hf_keys[stanza] |= set(keys)
        for other in [o for o in others if o.site == site]:
            for stanza, keys in sorted(_index_time_stanzas(ctx, other.name).items()):
                missing = sorted(set(keys) - hf_keys.get(stanza, set()))
                if not missing:
                    continue
                via_hf = sorted(seen_on_hf.get(stanza, set()) & {h.name for h in site_hfs})
                yield Finding(
                    "DATA-001",
                    f"Sourcetype {stanza}: index-time settings only on {other.role} {other.name}",
                    "high" if via_hf else "medium", "suspected", "data-integrity",
                    f"{site} / {other.name} / {stanza}",
                    servers=[other.name, *via_hf], sites=[site] if site else [],
                    evidence=[Evidence(server=other.name, path=keys[k], stanza=stanza, key=k) for k in missing]
                    + ([Evidence(search="sourcetype_by_forwarder",
                                 detail=f"sourcetype processed by {', '.join(via_hf)}")] if via_hf else []),
                    recommendation="Data arriving through an HF is parsed there; these settings have no "
                                   "effect for it. Move them to the HF TA (via DS); keep the indexer copy "
                                   "only if some data reaches indexers directly.")


@rule("DATA-002", "Same sourcetype defined differently in different apps", "data-integrity")
def conflicting_definitions(ctx: RunContext):
    values = defaultdict(lambda: defaultdict(set))  # (conf, stanza, key) -> value -> {(server, path, line)}
    for snap in ctx.servers():
        for e in ctx.files(snap.name):
            if e.conf not in ("props", "transforms") or e.location.root == "users":
                continue
            if e.conf == "props" and not _sourcetype_stanza(e.stanza):
                continue
            values[(e.conf, e.stanza, e.key)][e.value].add((snap.name, e.path, e.line, e.location.app))
    if not values:
        raise InsufficientData("no props/transforms files in snapshots")
    for (conf, stanza, key), by_value in sorted(values.items()):
        if len(by_value) < 2:
            continue
        apps = {app for places in by_value.values() for *_x, app in places}
        if len(apps) < 2:
            continue  # same app differing between servers is covered by app/config comparison
        servers = sorted({srv for places in by_value.values() for srv, *_ in places})
        yield Finding(
            "DATA-002", f"{conf}.conf [{stanza}] {key} has {len(by_value)} different values across apps",
            "medium", "proven", "data-integrity", f"{conf} / {stanza} / {key}", servers=servers,
            sites=sorted({ctx.by_name[s].site for s in servers if ctx.by_name[s].site}),
            evidence=[Evidence(server=srv, path=path, line=line, stanza=stanza, key=key, value=value)
                      for value, places in sorted(by_value.items()) for srv, path, line, _app in sorted(places)],
            recommendation="Keep one owning app per sourcetype; which value wins today depends on app "
                           "precedence on each server.")


def _ts(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


@rule("DATA-003", "Same origin host forwarded by several independent HFs", "data-integrity")
def duplicate_collection(ctx: RunContext):
    if not ctx.has_search("host_by_forwarder"):
        raise InsufficientData("host_by_forwarder search not collected")
    by_origin = defaultdict(dict)  # origin host -> hf name -> (first, last)
    for _sh, row in ctx.search_rows("host_by_forwarder"):
        snap = ctx.resolve(row.get("host", ""))
        if not snap or snap.role != "hf":
            continue
        by_origin[row.get("series", "")][snap.name] = (_ts(row.get("first_seen")), _ts(row.get("last_seen")))
    if not by_origin:
        raise NotApplicable("no forwarder metrics could be mapped to collected HFs")
    for origin, hfs in sorted(by_origin.items()):
        if len(hfs) < 2 or re.fullmatch(r"(?i)localhost|127\.0\.0\.1", origin):
            continue
        # Members of one HA group alternate on failover; count each group once.
        units = defaultdict(list)
        for name in hfs:
            snap = ctx.by_name[name]
            units[snap.ha_group or name].append(name)
        if len(units) < 2:
            continue
        sites = sorted({ctx.by_name[n].site for n in hfs if ctx.by_name[n].site})
        yield Finding(
            "DATA-003", f"Origin host {origin} arrives through {len(units)} independent HFs/groups",
            "high" if len(sites) > 1 else "medium", "suspected", "data-integrity", f"origin / {origin}",
            servers=sorted(hfs), sites=sites,
            evidence=[Evidence(server=n, search="host_by_forwarder",
                               detail=f"first {int(f)} last {int(l)}") for n, (f, l) in sorted(hfs.items())],
            recommendation="Check whether the same source is collected twice (two syslog targets, two "
                           "DB inputs, UF sending to both sites). Different sourcetypes from the same "
                           "host can be legitimate.")
