"""Input inventory, keepalived discovery and suggested environment settings (SPEC-004)."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from shx.conf.inputs import NEUTRAL_SCHEMES, PUSH_SCHEMES, app_of_source, scheme
from shx.rules.context import RunContext, is_true
from shx.snapshot import read_members

INPUT_FIELDS = ("sourcetype", "index", "interval", "connection", "mode", "host", "source")


def input_kind(stanza: str) -> str | None:
    s = scheme(stanza)
    if not s:
        return None
    if s in PUSH_SCHEMES:
        return "push"
    if s in NEUTRAL_SCHEMES:
        return "local"
    return "pull"


def _layer(source: str) -> str:
    parts = source.split("/")
    for layer in ("local", "default"):
        if layer in parts:
            return layer
    return ""


def input_rows(ctx: RunContext) -> tuple[list[dict], list[str]]:
    """One row per input stanza per server; plus servers without btool inputs."""
    rows, missing = [], []
    for snap in ctx.servers():
        eff = ctx.effective(snap.name)
        if "inputs" not in eff:
            missing.append(snap.name)
            continue
        checks = {c["stanza"]: c for c in snap.manifest.get("path_checks", [])}
        stanzas = [(st, kv, input_kind(st)) for st, kv in eff["inputs"].items()]
        stanzas += [(f"db_inputs://{st}", kv, "pull") for st, kv in eff.get("db_inputs", {}).items()
                    if st != "default"]
        for stanza, kv, kind in sorted(stanzas, key=lambda x: x[0]):
            if kind is None or not kv:
                continue
            disabled = kv.get("disabled")
            source = next(iter(kv.values())).source
            check = checks.get(stanza)
            rows.append({
                "server": snap.name, "role": snap.role, "site": snap.site or "",
                "ha_group": snap.ha_group or "", "app": app_of_source(source) or "system",
                "layer": _layer(source), "kind": kind, "scheme": scheme(stanza) or "db_input",
                "stanza": stanza, "enabled": not is_true(disabled.value if disabled else None),
                **{f: (kv[f].value if f in kv else "") for f in INPUT_FIELDS},
                "path_exists": "" if check is None else check["exists"],
                "source_file": source,
            })
    return rows, missing


# --- keepalived ---------------------------------------------------------------------

@dataclass
class VrrpInstance:
    server: str
    name: str
    state: str = ""
    router_id: str = ""
    priority: str = ""
    interface: str = ""
    vips: list[str] = field(default_factory=list)


_INSTANCE_RE = re.compile(r"^\s*vrrp_instance\s+(\S+)\s*\{")


def parse_keepalived(server: str, text: str) -> list[VrrpInstance]:
    instances, cur, depth, vip_depth = [], None, 0, None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split("!", 1)[0].strip()
        if not line:
            continue
        if cur is None:
            m = _INSTANCE_RE.match(line)
            if m:
                cur, depth = VrrpInstance(server, m.group(1)), 1
            continue
        words = line.replace("{", " { ").replace("}", " } ").split()
        if vip_depth is not None and words[0] not in "{}":
            cur.vips.append(words[0].split("/")[0])
        elif words[0] in ("state", "virtual_router_id", "priority", "interface") and len(words) > 1:
            setattr(cur, "router_id" if words[0] == "virtual_router_id" else words[0], words[1])
        elif words[0] == "virtual_ipaddress" and "{" in words:
            inner = words[words.index("{") + 1:]
            if inner and inner[0] != "}":
                cur.vips.append(inner[0].split("/")[0])
        for w in words:
            if w == "{":
                depth += 1
                if words[0] == "virtual_ipaddress":
                    vip_depth = depth
            elif w == "}":
                if vip_depth == depth:
                    vip_depth = None
                depth -= 1
        if depth <= 0:
            instances.append(cur)
            cur, depth, vip_depth = None, 0, None
    if cur is not None:
        instances.append(cur)
    return instances


def keepalived_instances(ctx: RunContext) -> list[VrrpInstance]:
    out = []
    for snap in ctx.servers():
        text = read_members(snap.archive, "system/keepalived.conf").get("system/keepalived.conf")
        if text:
            out += parse_keepalived(snap.name, text)
    return out


# --- suggestions --------------------------------------------------------------------

@dataclass
class Suggestions:
    ha_groups: dict[str, list[str]]           # suggested group name -> servers
    vips: list[str]
    pull_apps: dict[str, list[str]]           # server -> apps with enabled pull inputs
    duplicate_pull: list[tuple[str, list[str]]]  # (stanza, servers) running on several members
    notes: list[str]


def suggest(ctx: RunContext, rows: list[dict], instances: list[VrrpInstance]) -> Suggestions:
    notes = []
    # Servers sharing a VIP are one HA group.
    by_vip = defaultdict(set)
    names = {}
    for inst in instances:
        for vip in inst.vips:
            by_vip[vip].add(inst.server)
            names.setdefault(vip, inst.name)
    groups: dict[frozenset, set[str]] = {}
    for vip, servers in by_vip.items():
        key = frozenset(servers)
        groups.setdefault(key, set()).add(vip)
    ha_groups, vips = {}, set()
    for servers, group_vips in sorted(groups.items(), key=lambda x: sorted(x[0])):
        vips |= group_vips
        if len(servers) < 2:
            notes.append(f"{', '.join(sorted(servers))}: keepalived VIP {', '.join(sorted(group_vips))} "
                         "has no collected peer (peer not in the environment file?)")
            continue
        sites = {ctx.by_name[s].site for s in servers}
        site = next(iter(sites)) if len(sites) == 1 and None not in sites else "mixed"
        base = names[sorted(group_vips)[0]].lower().replace("_", "-")
        ha_groups[f"{site}-{base}"] = sorted(servers)
    # Declared groups count too (haproxy pools are not discoverable from Splunk hosts).
    members = {s: g for g, ss in ha_groups.items() for s in ss}
    for snap in ctx.servers("hf"):
        if snap.ha_group and snap.name not in members:
            members[snap.name] = snap.ha_group

    pull_by_server = defaultdict(set)
    stanza_servers = defaultdict(lambda: defaultdict(list))
    for r in rows:
        if r["kind"] == "pull" and r["enabled"] and r["server"] in members:
            pull_by_server[r["server"]].add(r["app"])
            stanza_servers[members[r["server"]]][r["stanza"]].append(r["server"])
    duplicates = [(st, sorted(ss)) for g in stanza_servers.values() for st, ss in g.items() if len(ss) > 1]
    return Suggestions(ha_groups, sorted(vips), {s: sorted(a) for s, a in sorted(pull_by_server.items())},
                       sorted(duplicates), notes)


def _toml_list(values) -> str:
    return "[" + ", ".join('"' + v.replace('"', '\\"') + '"' for v in values) + "]"


def suggestions_toml(s: Suggestions) -> str:
    """Valid TOML. Copy `vips` as is and each [suggested.<server>] block into that server's
    [[servers]] entry; the environment loader rejects a pasted `suggested` table on purpose."""
    lines = ["# Suggested additions to environments/<env>.toml - review before use.",
             "# Copy vips as is; copy each [suggested.<server>] block into that server's [[servers]] entry.", ""]
    if s.vips:
        lines += [f"vips = {_toml_list(s.vips)}", ""]
    per_server = {srv: g for g, ss in s.ha_groups.items() for srv in ss}
    for server in sorted(set(per_server) | set(s.pull_apps)):
        lines.append(f'[suggested."{server}"]')
        if server in per_server:
            lines.append(f'ha_group = "{per_server[server]}"')
        if server in s.pull_apps:
            lines.append(f"pull_apps = {_toml_list(s.pull_apps[server])}")
        lines.append("")
    for stanza, servers in s.duplicate_pull:
        lines.append(f"# WARNING: {stanza} is enabled on {', '.join(servers)} (same HA group): duplicates")
    for note in s.notes:
        lines.append(f"# NOTE: {note}")
    return "\n".join(lines).rstrip() + "\n"
