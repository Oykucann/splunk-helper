"""App inventory and comparison at three levels (SPEC-001, "App comparison").

- ha_group:   members of one HA group must be identical (installed apps).
- site:       servers with the same role inside one site.
- cross_site: the same role across sites, comparing each site as a whole.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from shx.snapshot import ServerSnapshot

INSTALLED_ROOTS = ("apps", "peer-apps", "slave-apps")
ABSENT = "-"


@dataclass(frozen=True)
class AppState:
    version: str | None
    state: str | None
    content_sha: str | None
    content_shape: str | None
    local_sha: str | None
    local_files: int

    @classmethod
    def from_manifest(cls, app: dict) -> "AppState":
        return cls(app.get("version") or app.get("manifest_version"), app.get("state"),
                   app.get("content_sha"), app.get("content_shape"), app.get("local_sha"),
                   app.get("local_files", 0))

    @property
    def label(self) -> str:
        v = self.version or "?"
        return f"{v} (disabled)" if self.state == "disabled" else v


@dataclass
class Difference:
    level: str      # ha_group | site | cross_site
    scope: str      # e.g. "site1-push", "site1/hf", "hf"
    root: str
    app: str
    kind: str       # presence | version | content | local | state
    values: dict[str, str] = field(default_factory=dict)  # server or site -> value

    @property
    def severity(self) -> str:
        if self.level == "ha_group":
            return "high"
        if self.kind in ("version", "content"):
            return "medium"
        return "info"


def inventory_rows(snapshots: list[ServerSnapshot]) -> list[dict]:
    rows = []
    for snap in snapshots:
        for app in snap.apps:
            rows.append({
                "server": snap.name, "role": snap.role, "site": snap.site or "",
                "ha_group": snap.ha_group or "", "root": app["root"], "app": app["name"],
                "version": app.get("version") or "", "manifest_version": app.get("manifest_version") or "",
                "build": app.get("build") or "", "state": app.get("state") or "",
                "local_only": app.get("local_only") or "", "local_files": app.get("local_files", 0),
                "content_sha": app.get("content_sha") or "", "content_shape": app.get("content_shape") or "",
                "local_sha": app.get("local_sha") or "",
            })
    return rows


def _states(snap: ServerSnapshot, roots) -> dict[tuple[str, str], AppState]:
    return {(a["root"], a["name"]): AppState.from_manifest(a) for a in snap.apps if a["root"] in roots}


def _content_key(s: AppState, all_have_sha: bool) -> str | None:
    return s.content_sha if all_have_sha else s.content_shape


def compare_members(level: str, scope: str, members: dict[str, dict], roots,
                    include_presence: bool) -> list[Difference]:
    """members: label (server name) -> {(root, app): AppState}."""
    diffs = []
    keys = sorted({k for states in members.values() for k in states if k[0] in roots})
    for root, app in keys:
        present = {m: states[(root, app)] for m, states in members.items() if (root, app) in states}
        if include_presence and len(present) != len(members):
            diffs.append(Difference(level, scope, root, app, "presence",
                                    {m: ("present" if m in present else ABSENT) for m in members}))
        if len(present) < 2:
            continue
        states = list(present.values())

        def differs(fn):
            return len({fn(s) for s in states}) > 1

        if differs(lambda s: s.version):
            diffs.append(Difference(level, scope, root, app, "version",
                                    {m: s.version or "?" for m, s in present.items()}))
        else:
            all_sha = all(s.content_sha for s in states)
            if differs(lambda s: _content_key(s, all_sha)):
                diffs.append(Difference(level, scope, root, app, "content",
                                        {m: _content_key(s, all_sha) or "?" for m, s in present.items()}))
        if differs(lambda s: s.state == "disabled"):
            diffs.append(Difference(level, scope, root, app, "state",
                                    {m: s.state or "enabled" for m, s in present.items()}))
        if differs(lambda s: s.local_sha):
            diffs.append(Difference(level, scope, root, app, "local",
                                    {m: f"{s.local_files} files {s.local_sha or ''}".strip()
                                     for m, s in present.items()}))
    return diffs


def compare_ha_groups(snapshots: list[ServerSnapshot]) -> list[Difference]:
    groups = defaultdict(dict)
    for s in snapshots:
        if s.ha_group:
            groups[s.ha_group][s.name] = _states(s, INSTALLED_ROOTS)
    diffs = []
    for group, members in sorted(groups.items()):
        if len(members) > 1:
            diffs += compare_members("ha_group", group, members, INSTALLED_ROOTS, include_presence=True)
    return diffs


def compare_within_sites(snapshots: list[ServerSnapshot]) -> list[Difference]:
    groups = defaultdict(dict)
    for s in snapshots:
        groups[(s.site or "", s.role)][s.name] = _states(s, _all_roots(snapshots))
    diffs = []
    for (site, role), members in sorted(groups.items()):
        if len(members) > 1:
            # HFs in a site legitimately differ in which apps they carry (pull vs push).
            diffs += compare_members("site", f"{site or 'no-site'}/{role}", members,
                                     _all_roots(snapshots), include_presence=role != "hf")
    return diffs


def compare_across_sites(snapshots: list[ServerSnapshot]) -> list[Difference]:
    by_role = defaultdict(lambda: defaultdict(list))
    for s in snapshots:
        if s.site:
            by_role[s.role][s.site].append(s)
    diffs = []
    for role, sites in sorted(by_role.items()):
        if len(sites) < 2:
            continue
        # Each site is represented by the union of its servers; a site whose servers disagree
        # shows every value it has (the site-level comparison explains why).
        site_values: dict[str, dict[tuple[str, str], set]] = {}
        for site, servers in sites.items():
            values = defaultdict(set)
            for srv in servers:
                for key, st in _states(srv, _all_roots(snapshots)).items():
                    values[key].add(st)
            site_values[site] = values
        keys = sorted({k for v in site_values.values() for k in v})
        for root, app in keys:
            present = {site: v[(root, app)] for site, v in site_values.items() if (root, app) in v}
            if len(present) != len(site_values):
                diffs.append(Difference("cross_site", role, root, app, "presence",
                                        {site: ("present" if site in present else ABSENT)
                                         for site in sorted(site_values)}))
            if len(present) < 2:
                continue
            versions = {site: frozenset(s.version or "?" for s in st) for site, st in present.items()}
            if len(set(versions.values())) > 1:
                diffs.append(Difference("cross_site", role, root, app, "version",
                                        {site: ", ".join(sorted(v)) for site, v in versions.items()}))
                continue
            all_sha = all(s.content_sha for st in present.values() for s in st)
            contents = {site: frozenset(_content_key(s, all_sha) for s in st) for site, st in present.items()}
            if len(set(contents.values())) > 1:
                diffs.append(Difference("cross_site", role, root, app, "content",
                                        {site: ", ".join(sorted(c or "?" for c in v))
                                         for site, v in contents.items()}))
    return diffs


def _all_roots(snapshots: list[ServerSnapshot]) -> tuple[str, ...]:
    return tuple(sorted({a["root"] for s in snapshots for a in s.apps}))


def compare_all(snapshots: list[ServerSnapshot]) -> list[Difference]:
    ha = compare_ha_groups(snapshots)
    seen = {(d.root, d.app, d.kind, tuple(sorted(d.values.items()))) for d in ha}
    # A site-level difference that is exactly an HA-group difference adds nothing.
    site = [d for d in compare_within_sites(snapshots)
            if (d.root, d.app, d.kind, tuple(sorted(d.values.items()))) not in seen]
    return ha + site + compare_across_sites(snapshots)
