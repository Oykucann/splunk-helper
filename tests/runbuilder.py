"""Build synthetic collection runs (run.json + snapshot tars + rest.json) for rule tests."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

HOME = "/data/splunk"


def bt(path: str, stanza: str, **kv) -> str:
    """btool --debug lines for one stanza; path relative to $SPLUNK_HOME."""
    full = f"{HOME}/{path}"
    lines = [f"{full} [{stanza}]"] + [f"{full} {k.replace('__', '.')} = {v}" for k, v in kv.items()]
    return "\n".join(lines) + "\n"


def app(name, version="1.0", root="apps", sha="c1", local=None, local_files=0, local_only=None):
    return {"name": name, "root": root, "path": f"etc/{root}/{name}", "version": version,
            "content_sha": None if local_only else sha, "content_shape": f"shape-{sha}",
            "local_sha": local, "local_files": local_files or (1 if local else 0),
            "local_only": local_only, "state": None}


def make_run(tmp: Path, servers: dict, rest: dict | None = None, env="test") -> Path:
    run = {"environment": env, "run_id": "r1", "servers": {}}
    for name, spec in servers.items():
        manifest = {"hostname": name, "apps": spec.get("apps", []), "files": spec.get("manifest_files", []),
                    "path_checks": spec.get("path_checks", []),
                    "splunk_version": spec.get("version", "VERSION=9.1.2"), "splunk_secret_sha256": "s"}
        members = {"manifest.json": json.dumps(manifest)}
        members |= {f"btool/{c}.txt": t for c, t in spec.get("btool", {}).items()}
        members |= spec.get("files", {})
        with tarfile.open(tmp / f"{name}.tar.gz", "w:gz") as tar:
            for mname, text in members.items():
                data = text.encode()
                info = tarfile.TarInfo(mname)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        run["servers"][name] = {"ok": True, "snapshot": f"{name}.tar.gz", "role": spec["role"],
                                "site": spec.get("site"), "ha_group": spec.get("ha"), "host": spec.get("host", name),
                                "pull_apps": spec.get("pull_apps", []), "also_roles": spec.get("also_roles", [])}
    for sh, searches in (rest or {}).items():
        payload = {"searches": {sid: {"ok": True, "results": rows} for sid, rows in searches.items()}}
        (tmp / f"{sh}.rest.json").write_text(json.dumps(payload))
        run["servers"].setdefault(sh, {"role": "sh"})["rest"] = {"ok": True, "file": f"{sh}.rest.json"}
    (tmp / "run.json").write_text(json.dumps(run))
    return tmp
