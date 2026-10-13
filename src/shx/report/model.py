"""Everything the HTML report shows, computed from one collection run (summary + detail JSON)."""

from __future__ import annotations

import fnmatch
import json
import re
import string
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from shx.apps import is_excluded, signature
from shx.conf.btool import parse as parse_btool
from shx.snapshot import ServerSnapshot, load_run

SYSTEM_CONFS = ("server", "web", "outputs", "deploymentclient", "distsearch", "limits",
                "authentication", "authorize", "health", "alert_actions")
# Stanzas Splunk writes or manages itself and nobody edits by hand; hidden from the
# server settings section (conf -> fnmatch patterns). Extend here when something else is noise.
EXCLUDED_STANZAS = {
    "server": ("lmpool:*", "introspection:*"),
}
UNIT_LIMIT_KEYS = ("LimitNOFILE", "LimitNPROC", "LimitCORE", "LimitFSIZE", "LimitDATA", "LimitAS",
                   "MemoryLimit", "MemoryMax", "MemoryHigh", "CPUQuota", "CPUShares", "CPUWeight",
                   "TasksMax", "User")
KIND_LABEL = {"builtin": "Splunk", "vendor": "vendor", "custom": ""}
UNSET = "—"
NOT_COLLECTED = "alınamadı"
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
        svc = s.summary.get("service") or {}
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
                              len(s.summary.get("errors", []))))
    return rows


# --- apps ---------------------------------------------------------------------------

@dataclass
class AppCopy:
    server: str
    root: str
    version: str
    kind: str
    letter: str = ""
    local_files: int = 0
    disabled: bool = False
    signature: tuple = ()
    content_id: tuple = ()  # version + shipped content; same id -> same letter

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
    def kind(self) -> str:
        return self.copies[0].kind if self.copies else "custom"

    @property
    def versions(self) -> list[str]:
        return sorted({c.version for c in self.copies}, key=version_key)

    @property
    def identical(self) -> bool:
        return len({c.signature for c in self.copies}) <= 1

    @property
    def newer_available(self) -> bool:
        return bool(self.latest) and all(version_key(self.latest) > version_key(v) for v in self.versions)


def _settings(detail: dict | None) -> dict[tuple, tuple[str, str]] | None:
    if detail is None or detail.get("missing") or detail.get("error"):
        return None
    merged = {}
    for layer in ("default", "local"):
        for lay, conf, stanza, key, value in detail.get("settings", []):
            if lay == layer:
                merged[(conf, stanza, key)] = (value, layer)
    return merged


def build_apps(snaps: list[ServerSnapshot], exclude=()) -> list[App]:
    apps: dict[str, App] = {}
    by_name = {s.name: s for s in snaps}
    for s in snaps:
        for a in s.apps:
            if is_excluded(a["name"], exclude):
                continue
            app = apps.setdefault(a["name"], App(a["name"]))
            app.copies.append(AppCopy(s.name, a["root"], a.get("version") or "sürüm yok", a.get("kind", "custom"),
                                      local_files=a.get("local_files") or 0, disabled=bool(a.get("disabled")),
                                      signature=signature(a), content_id=(a.get("version"), a.get("content_fp"))))
    for app in apps.values():
        app.copies.sort(key=lambda c: (c.server, c.root))
        letters: dict[tuple, str] = {}
        for c in app.copies:
            letters.setdefault(c.content_id, string.ascii_uppercase[len(letters) % 26])
            c.letter = letters[c.content_id]
        if app.identical:
            continue
        details = {c.where: by_name[c.server].app_detail(c.root, app.name) for c in app.copies}
        settings = {w: _settings(d) for w, d in details.items()}
        for conf, stanza, key in sorted({k for v in settings.values() if v for k in v}):
            values = {}
            for w, st in settings.items():
                if st is None:
                    values[w] = NOT_COLLECTED
                else:
                    hit = st.get((conf, stanza, key))
                    values[w] = UNSET if hit is None else hit[0] + (" (local)" if hit[1] == "local" else "")
            if len(set(values.values())) > 1:
                app.diffs.append(SettingDiff(conf, stanza, key, label_secrets(values)))
        files = {w: {rel: sha for rel, sha in (d or {}).get("files", [])} for w, d in details.items()}
        for rel in sorted({f for v in files.values() for f in v}):
            values = {w: v.get(rel, "yok") for w, v in files.items()}
            if len(set(values.values())) > 1:
                app.diffs.append(SettingDiff("dosya", rel, "", values))
        app.notes = _notes(app, details)
    return sorted(apps.values(), key=lambda a: (a.kind == "builtin", a.name.lower()))


def _notes(app: App, details: dict) -> list[str]:
    notes = []
    if len(app.versions) > 1:
        by_version = defaultdict(list)
        for c in app.copies:
            by_version[c.version].append(c.where)
        notes.append("Farklı sürümler: " + "; ".join(f"{v} → {', '.join(w)}" for v, w in
                                                      sorted(by_version.items(), key=lambda x: version_key(x[0]))))
    elif len({c.letter for c in app.copies}) > 1:
        notes.append("Aynı sürüm, farklı içerik.")
    local = [c.where for c in app.copies if c.local_files]
    if local:
        notes.append("local/ değişikliği olanlar: " + ", ".join(local))
    if app.kind in ("builtin", "vendor"):
        notes.append(f"{'Splunk' if app.kind == 'builtin' else 'Vendor'} app: yalnızca local/ ayarları karşılaştırıldı.")
    missing = [w for w, d in details.items() if _settings(d) is None]
    if missing:
        notes.append("Detayı alınamayanlar: " + ", ".join(missing))
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


def excluded(conf: str, stanza: str) -> bool:
    return any(fnmatch.fnmatchcase(stanza, p) for p in EXCLUDED_STANZAS.get(conf, ()))


def _source_app(path: str) -> str | None:
    parts = path.split("/")
    return parts[2] if len(parts) > 3 and parts[0] == "etc" and parts[1] != "system" else None


def build_system(snaps: list[ServerSnapshot], exclude=()) -> list[SystemRow]:
    btool = {s.name: {conf: parse_btool(text) for conf, text in (s.summary.get("btool") or {}).items()}
             for s in snaps}
    custom = set()
    for confs in btool.values():
        for conf in SYSTEM_CONFS:
            for stanza, kv in confs.get(conf, {}).items():
                if excluded(conf, stanza):
                    continue
                custom |= {(conf, stanza, k) for k, v in kv.items() if not v.is_system_default
                           and not is_excluded(_source_app(v.source) or "", exclude)}
    rows = []
    for conf, stanza, key in sorted(custom):
        values, sources = {}, {}
        for s in snaps:
            confs = btool.get(s.name, {})
            if conf not in confs:
                values[s.name] = "toplanmadı"
                continue
            setting = confs[conf].get(stanza, {}).get(key)
            if setting is not None and is_excluded(_source_app(setting.source) or "", exclude):
                values[s.name] = "hariç app"
                continue
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
    exclude_apps: tuple[str, ...] = ()


def build(run_dir: str | Path, env_path: str | Path | None = None) -> Report:
    run = json.loads((Path(run_dir) / "run.json").read_text())
    snaps = load_run(run_dir, env_path)
    exclude = tuple(run.get("exclude_apps") or ())
    if env_path:  # the current environment file wins, so exclusions apply without recollecting
        from shx.collect.environment import load as load_env
        exclude = load_env(env_path).exclude_apps
    return Report(run.get("environment", ""), run.get("run_id", ""), server_rows(snaps),
                  [s.name for s in snaps], build_apps(snaps, exclude), build_system(snaps, exclude),
                  exclude)
