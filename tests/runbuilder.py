"""Build synthetic collection runs (run.json + <server>.summary.json + <server>.detail.json)."""

from __future__ import annotations

import json
from pathlib import Path

HOME = "/data/splunk"


def bt(path: str, stanza: str, **kv) -> str:
    """btool --debug lines for one stanza; path relative to $SPLUNK_HOME."""
    full = f"{HOME}/{path}"
    lines = [f"{full} [{stanza}]"] + [f"{full} {k.replace('__', '.')} = {v}" for k, v in kv.items()]
    return "\n".join(lines) + "\n"


def app(name, version="1.0", root="apps", kind="custom", content="c1", local=None, local_files=0,
        disabled=False):
    """One entry of summary["apps"]."""
    return {"name": name, "root": root, "kind": kind, "version": version, "content_fp": content,
            "local_fp": local, "local_files": local_files or (1 if local else 0), "disabled": disabled}


def detail(name, root="apps", kind="custom", settings=(), files=()):
    """One entry of detail["apps"]: settings are (layer, conf, stanza, key, value)."""
    return {"name": name, "root": root, "kind": kind, "settings": [list(s) for s in settings],
            "files": [list(f) for f in files]}


def make_run(tmp: Path, servers: dict, env="test", exclude_apps=()) -> Path:
    run = {"environment": env, "run_id": "r1", "servers": {}, "exclude_apps": list(exclude_apps)}
    for name, spec in servers.items():
        summary = {"hostname": name, "apps": spec.get("apps", []), "btool": spec.get("btool", {}),
                   "service": spec.get("service", {}), "errors": spec.get("errors", [])}
        (tmp / f"{name}.summary.json").write_text(json.dumps(summary))
        entry = {"ok": True, "summary": f"{name}.summary.json", "role": spec["role"], "site": spec.get("site"),
                 "ha_group": spec.get("ha"), "host": spec.get("host", name),
                 "also_roles": spec.get("also_roles", [])}
        if spec.get("detail"):
            (tmp / f"{name}.detail.json").write_text(json.dumps({"apps": spec["detail"]}))
            entry["detail"] = f"{name}.detail.json"
        run["servers"][name] = entry
    (tmp / "run.json").write_text(json.dumps(run))
    return tmp
