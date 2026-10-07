"""Everything a rule may read about one collection run, loaded lazily."""

from __future__ import annotations

import json
from collections import defaultdict
from functools import cached_property
from pathlib import Path

from shx.conf.btool import EffectiveConf
from shx.conf.compare import effective_confs
from shx.conf.files import ConfEntry, parse_file
from shx.snapshot import ServerSnapshot, load_run, read_members

TRUE = {"1", "true", "t", "yes", "y", "on"}


def is_true(value: str | None) -> bool:
    return value is not None and value.strip().lower() in TRUE


class RunContext:
    def __init__(self, run_dir: str | Path, snapshots: list[ServerSnapshot] | None = None):
        self.run_dir = Path(run_dir)
        self.run = json.loads((self.run_dir / "run.json").read_text())
        self.snapshots = snapshots if snapshots is not None else load_run(self.run_dir)
        self.by_name = {s.name: s for s in self.snapshots}

    # --- servers ------------------------------------------------------------------

    def servers(self, role: str | None = None) -> list[ServerSnapshot]:
        return [s for s in self.snapshots if role is None or s.role == role]

    @cached_property
    def ha_groups(self) -> dict[str, list[ServerSnapshot]]:
        groups = defaultdict(list)
        for s in self.snapshots:
            if s.ha_group:
                groups[s.ha_group].append(s)
        return dict(groups)

    @cached_property
    def sites(self) -> list[str]:
        return sorted({s.site for s in self.snapshots if s.site})

    def aliases(self, snap: ServerSnapshot) -> set[str]:
        """Names a server may appear under in logs/metrics: env name, host, OS hostname, serverName."""
        names = {snap.name, self.run["servers"].get(snap.name, {}).get("host", "")}
        m = snap.manifest
        names |= {m.get("hostname") or "", (m.get("fqdn") or "").split(".")[0], m.get("fqdn") or ""}
        general = self.effective(snap.name).get("server", {}).get("general", {})
        if "serverName" in general:
            names.add(general["serverName"].value)
        return {n.lower() for n in names if n}

    @cached_property
    def alias_index(self) -> dict[str, ServerSnapshot]:
        return {alias: s for s in self.snapshots for alias in self.aliases(s)}

    def resolve(self, name: str) -> ServerSnapshot | None:
        return self.alias_index.get((name or "").lower())

    # --- configuration ------------------------------------------------------------

    @cached_property
    def _effective(self) -> dict[str, dict[str, EffectiveConf]]:
        return {s.name: effective_confs(s) for s in self.snapshots}

    def effective(self, server: str) -> dict[str, EffectiveConf]:
        return self._effective.get(server, {})

    def has_btool(self, server: str, conf: str) -> bool:
        return conf in self.effective(server)

    @cached_property
    def _files(self) -> dict[str, list[ConfEntry]]:
        out = {}
        for s in self.snapshots:
            entries = []
            for path, text in read_members(s.archive, "etc/").items():
                entries += parse_file(path, text)
            out[s.name] = entries
        return out

    def files(self, server: str, conf: str | None = None, root: str | None = None) -> list[ConfEntry]:
        return [e for e in self._files.get(server, [])
                if (conf is None or e.conf == conf) and (root is None or e.location.root == root)]

    # --- REST ---------------------------------------------------------------------

    @cached_property
    def rest(self) -> dict[str, dict]:
        """Search head name -> rest.json content."""
        out = {}
        for name, info in self.run["servers"].items():
            rest = info.get("rest") or {}
            if rest.get("file") and (self.run_dir / rest["file"]).exists():
                out[name] = json.loads((self.run_dir / rest["file"]).read_text())
        return out

    def rest_site(self, sh_name: str) -> str | None:
        return self.run["servers"].get(sh_name, {}).get("site")

    def search_rows(self, search_id: str) -> list[tuple[str, dict]]:
        """(search head name, row) for every successful run of a search."""
        rows = []
        for sh, data in self.rest.items():
            res = data.get("searches", {}).get(search_id)
            if res and res.get("ok"):
                rows += [(sh, r) for r in res.get("results", [])]
        return rows

    def has_search(self, search_id: str) -> bool:
        return any(d.get("searches", {}).get(search_id, {}).get("ok") for d in self.rest.values())
