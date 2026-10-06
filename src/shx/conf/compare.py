"""Effective-config comparison between servers and sites (SPEC-001, "Config comparison").

Same three levels as the app comparison:
- ha_group:   every btool conf, members must be identical
- site:       system confs, same role within a site
- cross_site: system confs + indexes, same role across sites (each site = union of servers)

Only settings customised somewhere (not sourced from etc/system/default on every member)
are compared, so stock defaults don't produce noise.
"""

from __future__ import annotations

import fnmatch
import tomllib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from shx.conf.btool import EffectiveConf, Setting, parse
from shx.snapshot import ServerSnapshot, read_members

SYSTEM_CONFS = ("server", "web", "limits", "authentication", "authorize", "distsearch",
                "outputs", "deploymentclient", "health", "alert_actions", "_instance")
CROSS_SITE_CONFS = SYSTEM_CONFS + ("indexes",)
UNSET = "(unset)"
EXPECTATIONS_FILE = Path(__file__).resolve().parent.parent / "knowledge" / "conf_expectations.toml"

_TRUE = {"true", "1", "yes", "t", "on", "y"}
_FALSE = {"false", "0", "no", "f", "off", "n"}


@dataclass(frozen=True)
class Expectation:
    expect: str = "should_match"
    note: str = ""


class Expectations:
    def __init__(self, rules: list[dict]):
        self.rules = rules

    @classmethod
    def load(cls, path: Path = EXPECTATIONS_FILE) -> "Expectations":
        return cls(tomllib.loads(path.read_text()).get("rule", []))

    def lookup(self, conf: str, stanza: str, key: str) -> Expectation:
        for r in self.rules:
            if (_match(conf, r["conf"]) and _match(stanza, r["stanza"]) and _match(key, r["key"])):
                return Expectation(r["expect"], r.get("note", ""))
        return Expectation()


def _match(value: str, patterns: str) -> bool:
    return any(fnmatch.fnmatchcase(value, p) for p in patterns.split("|"))


def normalize(value: str) -> str:
    v = " ".join(value.split())
    low = v.lower()
    if low in _TRUE:
        return "true"
    if low in _FALSE:
        return "false"
    return v


@dataclass
class ConfDifference:
    level: str
    scope: str
    conf: str
    stanza: str
    key: str
    expect: str
    note: str
    values: dict[str, str] = field(default_factory=dict)

    @property
    def severity(self) -> str:
        if self.expect == "must_match":
            return "high"
        if self.level == "cross_site" and self.expect == "per_site":
            return "decision"  # expected today; must be resolved for the target
        if self.level == "ha_group":
            return "high"
        return "medium"


def effective_confs(snap: ServerSnapshot) -> dict[str, EffectiveConf]:
    confs = {}
    for name, text in read_members(snap.archive, "btool/").items():
        confs[Path(name).stem] = parse(text)
    m = snap.manifest
    confs["_instance"] = {"instance": {
        "splunk_version": Setting(m.get("splunk_version") or UNSET, "manifest"),
        "splunk_secret_sha256": Setting(m.get("splunk_secret_sha256") or UNSET, "manifest"),
    }}
    return confs


def compare_members(level: str, scope: str, members: dict[str, list[dict[str, EffectiveConf]]],
                    confs, expectations: Expectations) -> list[ConfDifference]:
    """members: label (server or site) -> effective confs of each server in it."""
    diffs = []
    present_confs = sorted({c for servers in members.values() for s in servers for c in s} & set(confs))
    for conf in present_confs:
        keys = sorted({(stanza, key)
                       for servers in members.values() for s in servers
                       for stanza, kv in s.get(conf, {}).items() for key in kv})
        for stanza, key in keys:
            exp = expectations.lookup(conf, stanza, key)
            if exp.expect in ("per_server", "ignore"):
                continue
            settings = {label: [s.get(conf, {}).get(stanza, {}).get(key) for s in servers]
                        for label, servers in members.items()}
            all_settings = [x for xs in settings.values() for x in xs]
            if all(x is not None and x.is_system_default for x in all_settings):
                continue
            values = {label: frozenset(normalize(x.value) if x else UNSET for x in xs)
                      for label, xs in settings.items()}
            if len(set(values.values())) > 1:
                diffs.append(ConfDifference(level, scope, conf, stanza, key, exp.expect, exp.note,
                                            {label: " / ".join(sorted(v)) for label, v in values.items()}))
    return diffs


def compare_all(snapshots: list[ServerSnapshot], expectations: Expectations | None = None,
                confs_by_server: dict[str, dict[str, EffectiveConf]] | None = None) -> list[ConfDifference]:
    expectations = expectations or Expectations.load()
    eff = confs_by_server or {s.name: effective_confs(s) for s in snapshots}
    diffs: list[ConfDifference] = []

    ha = defaultdict(dict)
    for s in snapshots:
        if s.ha_group:
            ha[s.ha_group][s.name] = [eff[s.name]]
    for group, members in sorted(ha.items()):
        if len(members) > 1:
            all_confs = sorted({c for m in members.values() for c in m[0]})
            diffs += compare_members("ha_group", group, members, all_confs, expectations)
    seen = {(d.conf, d.stanza, d.key, tuple(sorted(d.values.items()))) for d in diffs}

    site = defaultdict(dict)
    for s in snapshots:
        site[(s.site or "no-site", s.role)][s.name] = [eff[s.name]]
    for (site_name, role), members in sorted(site.items()):
        if len(members) > 1:
            diffs += [d for d in compare_members("site", f"{site_name}/{role}", members, SYSTEM_CONFS,
                                                 expectations)
                      if (d.conf, d.stanza, d.key, tuple(sorted(d.values.items()))) not in seen]

    cross = defaultdict(lambda: defaultdict(list))
    for s in snapshots:
        if s.site:
            cross[s.role][s.site].append(eff[s.name])
    for role, sites in sorted(cross.items()):
        if len(sites) > 1:
            diffs += compare_members("cross_site", role, dict(sites), CROSS_SITE_CONFS, expectations)
    return diffs
