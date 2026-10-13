"""Where each app lives, in which version/variant, and what differs between the copies.

A location is (server, app root): `apps` (installed), `manager-apps` (CM → indexers),
`deployment-apps` (DS → HF/UF), `shcluster/apps` (deployer → SHC), `peer-apps`, ...
"""

from __future__ import annotations

import string
from collections import defaultdict
from dataclasses import dataclass

from shx.report.common import UNSET, label_secrets
from shx.rules.context import RunContext

ROOT_ORDER = ("apps", "peer-apps", "slave-apps", "manager-apps", "master-apps", "shcluster/apps",
              "deployment-apps")


@dataclass(frozen=True)
class Loc:
    server: str
    site: str
    root: str

    @property
    def column(self) -> str:
        return f"{self.site}/{self.server}/{self.root}"

    @property
    def sort_key(self):
        return (self.site, self.server, ROOT_ORDER.index(self.root) if self.root in ROOT_ORDER else 99)


def app_locations(ctx: RunContext) -> dict[str, dict[Loc, dict]]:
    out = defaultdict(dict)
    for snap in ctx.servers():
        for a in snap.apps:
            out[a["name"]][Loc(snap.name, snap.site or "no-site", a["root"])] = a
    return out


def all_locations(apps: dict[str, dict[Loc, dict]]) -> list[Loc]:
    return sorted({loc for locs in apps.values() for loc in locs}, key=lambda l: l.sort_key)


def _content_id(a: dict) -> tuple:
    return (a.get("version") or a.get("manifest_version") or "?",
            a.get("content_sha") or ("shape:" + (a.get("content_shape") or "")))


def variant_labels(locs: dict[Loc, dict]) -> dict[Loc, str]:
    """Same letter = same version and same shipped content (local/ not included)."""
    ids, labels = {}, {}
    for loc in sorted(locs, key=lambda l: l.sort_key):
        cid = _content_id(locs[loc])
        ids.setdefault(cid, string.ascii_uppercase[len(ids) % 26])
        labels[loc] = ids[cid]
    return labels


def _needs_detail(locs: dict[Loc, dict]) -> bool:
    if len(locs) < 2:
        return False
    return len({_content_id(a) for a in locs.values()}) > 1 or len({a.get("local_sha") for a in locs.values()}) > 1


def apps_table(ctx: RunContext) -> tuple[list[dict], list[str]]:
    apps = app_locations(ctx)
    locs_all = all_locations(apps)
    rows = []
    for name in sorted(apps, key=str.lower):
        locs = apps[name]
        labels = variant_labels(locs)
        row = {
            "app": name,
            "locations": len(locs),
            "variants": len(set(labels.values())),
            "versions": ", ".join(sorted({a.get("version") or "?" for a in locs.values()})),
            "with_local": sum(1 for a in locs.values() if a.get("local_files")),
            "vendor_local_only": "yes" if any(a.get("local_only") for a in locs.values()) else "",
        }
        for loc, a in locs.items():
            cell = f"{a.get('version') or '?'} {labels[loc]}"
            if a.get("local_files"):
                cell += " +local"
            if (a.get("state") or "").lower() == "disabled":
                cell += " disabled"
            row[loc.column] = cell
        rows.append(row)
    columns = ["app", "locations", "variants", "versions", "with_local", "vendor_local_only"] + \
        [l.column for l in locs_all]
    return rows, columns


def _app_settings(ctx: RunContext, loc: Loc, app: str) -> dict[tuple, tuple[str, str]]:
    """(conf, stanza, key) -> (value, layer); local overrides default inside the app."""
    merged = {}
    for layer in ("default", "local"):
        for e in ctx.files(loc.server, root=loc.root):
            if e.location.app == app and e.location.layer == layer:
                merged[(e.conf, e.stanza, e.key)] = (e.value, layer)
    return merged


def _app_files(snap, loc: Loc, app: str) -> dict[str, str]:
    prefix = f"etc/{loc.root}/{app}/"
    return {f["path"][len(prefix):]: (f.get("sha256") or "?")[:10]
            for f in snap.manifest.get("files", [])
            if f["path"].startswith(prefix) and f.get("kind") != "conf"}


def app_settings_table(ctx: RunContext) -> tuple[list[dict], list[str]]:
    """Only apps whose copies differ; only keys/files whose values differ between copies."""
    apps = app_locations(ctx)
    locs_all = all_locations(apps)
    rows = []
    for name in sorted(apps, key=str.lower):
        locs = apps[name]
        if not _needs_detail(locs):
            continue
        labels = variant_labels(locs)
        scope = "local/ only (vendor default not collected)" if any(a.get("local_only") for a in locs.values()) else ""
        settings = {loc: _app_settings(ctx, loc, name) for loc in locs}
        keys = sorted({k for s in settings.values() for k in s})
        for conf, stanza, key in keys:
            values = {}
            for loc in locs:
                hit = settings[loc].get((conf, stanza, key))
                values[loc.column] = UNSET if hit is None else hit[0] + (" [local]" if hit[1] == "local" else "")
            if len({v.replace(" [local]", "") for v in values.values()}) == 1 and \
                    len(set(values.values())) == 1:
                continue
            rows.append({"app": name, "conf": conf, "stanza": stanza, "key": key, "scope": scope,
                         "variants": " ".join(f"{l.column}={labels[l]}" for l in sorted(locs, key=lambda l: l.sort_key)),
                         **label_secrets(values)})
        files = {loc: _app_files(ctx.by_name[loc.server], loc, name) for loc in locs}
        for rel in sorted({f for fs in files.values() for f in fs}):
            values = {loc.column: files[loc].get(rel, "(missing)") for loc in locs}
            if len(set(values.values())) > 1:
                rows.append({"app": name, "conf": "(file)", "stanza": rel, "key": "sha256", "scope": scope,
                             "variants": "", **values})
    columns = ["app", "conf", "stanza", "key", "scope"] + [l.column for l in locs_all] + ["variants"]
    return rows, columns
