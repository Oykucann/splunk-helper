"""Read a collection run (snapshots/<env>/<run_id>/) produced by shx-collect."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ServerSnapshot:
    name: str
    role: str
    site: str | None
    ha_group: str | None
    summary: dict
    detail: dict = field(default_factory=dict)   # phase 2; empty when nothing differed
    also_roles: tuple[str, ...] = ()

    @property
    def roles(self) -> tuple[str, ...]:
        return (self.role, *self.also_roles)

    @property
    def role_label(self) -> str:
        return "+".join(self.roles)

    @property
    def apps(self) -> list[dict]:
        return self.summary.get("apps", [])

    def app_detail(self, root: str, name: str) -> dict | None:
        for a in self.detail.get("apps", []):
            if a.get("root") == root and a.get("name") == name:
                return a
        return None


def load_run(run_dir: str | Path, env_path: str | Path | None = None) -> list[ServerSnapshot]:
    """Snapshots of a run. With `env_path`, role/site/ha_group come from the current
    environment file instead of run.json, so labels can be fixed without recollecting."""
    run_dir = Path(run_dir)
    run = json.loads((run_dir / "run.json").read_text())
    overrides = {}
    if env_path:
        from shx.collect.environment import load as load_env
        overrides = {s.name: {"role": s.role, "site": s.site, "ha_group": s.ha_group,
                              "also_roles": list(s.also_roles)} for s in load_env(env_path).servers}
    snapshots = []
    for name, info in sorted(run["servers"].items()):
        if not info.get("ok"):
            continue
        info = {**info, **overrides.get(name, {})}
        summary = json.loads((run_dir / info["summary"]).read_text())
        detail_file = info.get("detail")
        detail = json.loads((run_dir / detail_file).read_text()) if detail_file else {}
        snapshots.append(ServerSnapshot(
            name=name, role=info["role"], site=info.get("site"), ha_group=info.get("ha_group"),
            summary=summary, detail=detail, also_roles=tuple(info.get("also_roles") or ()),
        ))
    return snapshots
