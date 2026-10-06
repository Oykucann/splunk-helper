"""Read a collection run (snapshots/<env>/<run_id>/) produced by shx-collect."""

from __future__ import annotations

import json
import tarfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ServerSnapshot:
    name: str
    role: str
    site: str | None
    ha_group: str | None
    manifest: dict
    archive: Path

    @property
    def apps(self) -> list[dict]:
        return self.manifest.get("apps", [])


def read_manifest(archive: Path) -> dict:
    with tarfile.open(archive, "r:gz") as tar:
        return json.load(tar.extractfile("manifest.json"))


def read_members(archive: Path, prefix: str) -> dict[str, str]:
    """All text members under `prefix`, in one pass over the archive."""
    out = {}
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            if member.isfile() and member.name.startswith(prefix):
                out[member.name] = tar.extractfile(member).read().decode("utf-8", "replace")
    return out


def load_run(run_dir: str | Path) -> list[ServerSnapshot]:
    run_dir = Path(run_dir)
    run = json.loads((run_dir / "run.json").read_text())
    snapshots = []
    for name, info in sorted(run["servers"].items()):
        if not info.get("ok"):
            continue
        archive = run_dir / info["snapshot"]
        snapshots.append(ServerSnapshot(
            name=name, role=info["role"], site=info.get("site"), ha_group=info.get("ha_group"),
            manifest=read_manifest(archive), archive=archive,
        ))
    return snapshots
