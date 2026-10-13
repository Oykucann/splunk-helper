"""Everything the HTML report shows, computed from one collection run."""

from __future__ import annotations

import re
import string
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from shx.conf.btool import parse as parse_btool
from shx.conf.files import parse_file
from shx.snapshot import ServerSnapshot, load_run, read_members

# Instance-level confs shown from btool (non-default settings only).
SYSTEM_CONFS = ("server", "web", "outputs", "deploymentclient", "distsearch", "limits",
                "authentication", "authorize", "health", "alert_actions")
UNIT_LIMIT_KEYS = ("LimitNOFILE", "LimitNPROC", "LimitCORE", "LimitFSIZE", "LimitDATA", "LimitAS",
                   "MemoryLimit", "MemoryMax", "MemoryHigh", "CPUQuota", "CPUShares", "CPUWeight",
                   "TasksMax", "User")
UNSET = "—"
_REDACTED_RE = re.compile(r"<redacted(?::(enc|plain))?(?::([0-9a-f]+))?>")


def label_secrets(values: dict[str, str]) -> dict[str, str]:
    """Equal secrets get the same label within a row; nothing is assumed to be shared."""
    labels: dict[str, str] = {}

    def sub(m):
        fp = m.group(2)
        if not fp:
            return "secret"
        labels.setdefault(fp, f"secret#{len(labels) + 1}")
        return labels[fp]
    return {k: _REDACTED_RE.sub(sub, v) for k, v in values.items()}


def version_key(v: str | None) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


# --- servers / service --------------------------------------------------------------

@dataclass
class ServerRow:
    name: str
    role: str
    site: str
    product: str
    version: str
    running: str
    service: str
    limits: str
    errors: int


def server_rows(snaps: list[ServerSnapshot]) -> list[ServerRow]:
    rows = []
    for s in snaps:
        svc = s.manifest.get("service") or {}
        installs = svc.get("installs") or []
        product = ", ".join(f"{i.get('product')} ({i['home']})" for i in installs) or "Splunk bulunamadı"
        version = ", ".join(i.get("version") or "?" for i in installs)
        running = ", ".join(("çalışıyor" + (f" ({i['run_user']})" if i.get("run_user") else ""))
                            if i.get("running") else "çalışmıyor" for i in installs) or UNSET
        units = svc.get("systemd_units") or []
        service = "; ".join(f"{u['unit']} ({'enabled' if u.get('enabled') else 'disabled'})" for u in units)
        if svc.get("initd_script"):
            service = (service + "; " if service else "") + "/etc/init.d/splunk"
        limits = []
        for u in units:
            limits += [f"{k}={v}" for k, v in u.get("settings", {}).items() if k in UNIT_LIMIT_KEYS]
        for i in installs:
            pl = i.get("process_limits") or {}
            for name, short in (("Max open files", "nofile"), ("Max processes", "nproc")):
                if isinstance(pl.get(name), dict):
                    limits.append(f"proses {short}={pl[name]['soft']}/{pl[name]['hard']}")
        rows.append(ServerRow(s.name, s.role_label, s.site or "", product, version, running,
                              service or "systemd/init.d servisi yok", ", ".join(limits) or UNSET,
                              len(s.manifest.get("errors", []))))
    return rows


# --- apps ---------------------------------------------------------------------------

@dataclass
class AppCopy:
    server: str
    root: str
    version: str
    letter: str = ""
    local_files: int = 0
    disabled: bool = False
    vendor_local_only: bool = False
    content: tuple = ()
    local_sha: str | None = None

    @property
    def where(self) -> str:
        return self.server if self.root == "apps" else f"{self.server}:{self.root}"


@dataclass
class SettingDiff:
    conf: str
    stanza: str
    key: str
    values: dict[str, str]  # copy.where -> value


@dataclass
class App:
    name: str
    copies: list[AppCopy] = field(default_factory=list)
    diffs: list[SettingDiff] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    latest: str | None = None
    url: str | None = None

    @property
    def versions(self) -> list[str]:
        return sorted({c.version for c in self.copies}, key=version_key)

    @property
    def newer_available(self) -> bool:
        return bool(self.latest) and all(version_key(self.latest) > version_key(v) for v in self.versions)


def _app_conf(entries, root: str, app: str) -> dict[tuple, tuple[str, str]]:
    merged = {}
    for layer in ("default", "local"):
        for e in entries:
            if e.location.root == root and e.location.app == app and e.location.layer == layer:
                merged[(e.conf, e.stanza, e.key)] = (e.value, layer)
    return merged


def _app_files(snap: ServerSnapshot, root: str, app: str) -> dict[str, str]:
    prefix = f"etc/{root}/{app}/"
    return {f["path"][len(prefix):]: (f.get("sha256") or "?")[:10] for f in snap.manifest.get("files", [])
            if f["path"].startswith(prefix) and f.get("kind") != "conf"}


def build_apps(snaps: list[ServerSnapshot], conf_entries: dict[str, list]) -> list[App]:
    apps: dict[str, App] = {}
    for s in snaps:
        for a in s.apps:
            app = apps.setdefault(a["name"], App(a["name"]))
            app.copies.append(AppCopy(
                s.name, a["root"], a.get("version") or a.get("manifest_version") or "sürüm yok",
                local_files=a.get("local_files") or 0,
                disabled=(a.get("state") or "").lower() == "disabled",
                vendor_local_only=bool(a.get("local_only")),
                content=(a.get("version"), a.get("content_sha") or a.get("content_shape")),
                local_sha=a.get("local_sha")))
    by_name = {s.name: s for s in snaps}
    for app in apps.values():
        app.copies.sort(key=lambda c: (c.server, c.root))
        letters: dict[tuple, str] = {}
        for c in app.copies:
            letters.setdefault(c.content, string.ascii_uppercase[len(letters) % 26])
            c.letter = letters[c.content]
        if len(app.copies) < 2:
            continue
        settings = {c.where: _app_conf(conf_entries[c.server], c.root, app.name) for c in app.copies}
        for conf, stanza, key in sorted({k for v in settings.values() for k in v}):
            values = {}
            for c in app.copies:
                hit = settings[c.where].get((conf, stanza, key))
                values[c.where] = UNSET if hit is None else hit[0] + (" (local)" if hit[1] == "local" else "")
            if len(set(values.values())) > 1:
                app.diffs.append(SettingDiff(conf, stanza, key, label_secrets(values)))
        files = {c.where: _app_files(by_name[c.server], c.root, app.name) for c in app.copies}
        for rel in sorted({f for v in files.values() for f in v}):
            values = {w: v.get(rel, "yok") for w, v in files.items()}
            if len(set(values.values())) > 1:
                app.diffs.append(SettingDiff("dosya", rel, "", values))
        app.notes = _notes(app)
    return sorted(apps.values(), key=lambda a: a.name.lower())


def _notes(app: App) -> list[str]:
    notes = []
    if len(app.versions) > 1:
        by_version = defaultdict(list)
        for c in app.copies:
            by_version[c.version].append(c.where)
        notes.append("Farklı sürümler: " + "; ".join(f"{v} → {', '.join(w)}" for v, w in
                                                      sorted(by_version.items(), key=lambda x: version_key(x[0]))))
    elif len({c.letter for c in app.copies}) > 1:
        notes.append("Aynı sürüm, farklı içerik (default/ dosyaları değiştirilmiş).")
    local = [c.where for c in app.copies if c.local_files]
    if local:
        notes.append("local/ değişikliği olanlar: " + ", ".join(local))
    if any(c.vendor_local_only for c in app.copies):
        notes.append("Vendor app: yalnızca local/ karşılaştırıldı.")
    return notes


# --- btool system settings ----------------------------------------------------------

@dataclass
class SystemRow:
    conf: str
    stanza: str
    key: str
    values: dict[str, str]  # server -> value
    sources: dict[str, str]

    @property
    def differs(self) -> bool:
        return len({v for v in self.values.values() if v != "toplanmadı"}) > 1


def _source(path: str) -> str:
    parts = path.split("/")
    if parts[:3] == ["etc", "system", "local"]:
        return "system/local"
    return "/".join(parts[1:3]) if len(parts) > 3 else path


def build_system(snaps: list[ServerSnapshot], btool: dict[str, dict]) -> list[SystemRow]:
    custom = set()
    for name, confs in btool.items():
        for conf in SYSTEM_CONFS:
            for stanza, kv in confs.get(conf, {}).items():
                custom |= {(conf, stanza, k) for k, v in kv.items() if not v.is_system_default}
    rows = []
    for conf, stanza, key in sorted(custom):
        values, sources = {}, {}
        for s in snaps:
            confs = btool.get(s.name, {})
            if conf not in confs:
                values[s.name] = "toplanmadı"
                continue
            setting = confs[conf].get(stanza, {}).get(key)
            values[s.name] = UNSET if setting is None else " ".join(setting.value.split())
            if setting is not None and not setting.is_system_default:
                sources[s.name] = _source(setting.source)
        rows.append(SystemRow(conf, stanza, key, label_secrets(values), sources))
    return rows


# --- whole report -------------------------------------------------------------------

@dataclass
class Report:
    environment: str
    run_id: str
    servers: list[ServerRow]
    server_names: list[str]
    apps: list[App]
    system: list[SystemRow]


def build(run_dir: str | Path, env_path: str | Path | None = None) -> Report:
    import json
    run = json.loads((Path(run_dir) / "run.json").read_text())
    snaps = load_run(run_dir, env_path)
    conf_entries, btool = {}, {}
    for s in snaps:
        entries = []
        for path, text in read_members(s.archive, "etc/").items():
            entries += parse_file(path, text)
        conf_entries[s.name] = entries
        btool[s.name] = {Path(p).stem: parse_btool(t) for p, t in read_members(s.archive, "btool/").items()}
    return Report(run.get("environment", ""), run.get("run_id", ""), server_rows(snaps),
                  [s.name for s in snaps], build_apps(snaps, conf_entries), build_system(snaps, btool))
