"""Parse the raw .conf files copied into a snapshot, keeping app, layer and line numbers."""

from __future__ import annotations

from dataclasses import dataclass

APP_ROOTS = ("apps", "peer-apps", "slave-apps", "deployment-apps", "manager-apps",
             "master-apps", "shcluster/apps")


@dataclass(frozen=True)
class Location:
    root: str            # apps, deployment-apps, system, users, ...
    app: str | None
    layer: str           # default | local
    user: str | None = None


@dataclass(frozen=True)
class ConfEntry:
    path: str            # etc/apps/TA-x/local/props.conf
    location: Location
    conf: str            # props
    stanza: str
    key: str
    value: str
    line: int


def locate(path: str) -> Location | None:
    parts = path.split("/")
    if len(parts) < 3 or parts[0] != "etc" or not parts[-1].endswith(".conf"):
        return None
    if parts[1] == "system" and len(parts) == 4:
        return Location("system", None, parts[2])
    if parts[1] == "users" and len(parts) == 6:
        return Location("users", parts[3], parts[4], user=parts[2])
    for root in APP_ROOTS:
        rparts = root.split("/")
        if parts[1:1 + len(rparts)] == rparts and len(parts) == 1 + len(rparts) + 3:
            app, layer = parts[1 + len(rparts)], parts[2 + len(rparts)]
            if layer in ("default", "local"):
                return Location(root, app, layer)
    return None


def parse_file(path: str, text: str) -> list[ConfEntry]:
    loc = locate(path)
    if loc is None:
        return []
    conf = path.rsplit("/", 1)[1][:-len(".conf")]
    entries = []
    stanza = "default"
    pending = None  # (key, value_parts, line)
    for no, raw in enumerate(text.splitlines(), 1):
        if pending:
            key, parts, start = pending
            parts.append(raw.strip())
            if raw.rstrip().endswith("\\"):
                continue
            entries.append(ConfEntry(path, loc, conf, stanza, key, "\n".join(parts), start))
            pending = None
            continue
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            stanza = line[1:-1].strip()
            continue
        if "=" not in line:
            continue
        key, value = (x.strip() for x in line.split("=", 1))
        if value.endswith("\\"):
            pending = (key, [value], no)
            continue
        entries.append(ConfEntry(path, loc, conf, stanza, key, value, no))
    if pending:
        key, parts, start = pending
        entries.append(ConfEntry(path, loc, conf, stanza, key, "\n".join(parts), start))
    return entries
