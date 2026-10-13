"""Instance-level settings: what in server.conf, web.conf, outputs.conf, ... is not stock,
on which server, and from which file (system/local or an app)."""

from __future__ import annotations

from shx.report.common import UNSET, label_secrets, server_column
from shx.rules.context import RunContext

SYSTEM_CONFS = ("server", "web", "outputs", "deploymentclient", "distsearch", "authentication",
                "authorize", "limits", "health", "alert_actions", "inputs")
# inputs.conf: only the instance-wide stanzas; individual inputs are in the inventory.
INPUT_STANZAS = {"default", "http", "SSL", "splunktcp"}
NOT_COLLECTED = "(not collected)"


def _source_label(source: str) -> str:
    parts = source.split("/")
    if parts[:3] == ["etc", "system", "local"]:
        return "system/local"
    if len(parts) >= 4 and parts[0] == "etc":
        return "/".join(parts[1:4])  # apps/<app>/local
    return source


def system_table(ctx: RunContext) -> tuple[list[dict], list[str]]:
    servers = ctx.servers()
    cols = {s.name: server_column(s) for s in servers}
    eff = {s.name: ctx.effective(s.name) for s in servers}

    customised = set()
    for name, confs in eff.items():
        for conf in SYSTEM_CONFS:
            for stanza, kv in confs.get(conf, {}).items():
                if conf == "inputs" and stanza not in INPUT_STANZAS:
                    continue
                for key, setting in kv.items():
                    if not setting.is_system_default:
                        customised.add((conf, stanza, key))

    rows = []
    for key, getter in (("splunk_version", lambda s: s.manifest.get("splunk_version") or ""),
                        ("splunk.secret", lambda s: f"<redacted:{(s.manifest.get('splunk_secret_sha256') or '')[:12]}>"
                         if s.manifest.get("splunk_secret_sha256") else "")):
        values = {cols[s.name]: getter(s) for s in servers}
        rows.append({"conf": "(instance)", "stanza": "", "key": key,
                     "differs": "yes" if len(set(values.values())) > 1 else "",
                     "sources": "", **label_secrets(values)})

    for conf, stanza, key in sorted(customised):
        values, sources = {}, []
        for s in servers:
            confs = eff[s.name]
            if conf not in confs:
                values[cols[s.name]] = NOT_COLLECTED
                continue
            setting = confs[conf].get(stanza, {}).get(key)
            if setting is None:
                values[cols[s.name]] = UNSET
                continue
            values[cols[s.name]] = " ".join(setting.value.split())
            if not setting.is_system_default:
                sources.append(f"{s.name}={_source_label(setting.source)}")
        compared = {v for v in values.values() if v != NOT_COLLECTED}
        rows.append({"conf": conf, "stanza": stanza, "key": key,
                     "differs": "yes" if len(compared) > 1 else "",
                     "sources": "; ".join(sources), **label_secrets(values)})
    columns = ["conf", "stanza", "key", "differs"] + [cols[s.name] for s in servers] + ["sources"]
    return rows, columns
