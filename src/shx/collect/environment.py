"""Environment definition (environments/<name>.toml)."""

from __future__ import annotations

import socket
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROLES = ("sh", "deployer", "cm", "ds", "idx", "hf")
# Collection order: least critical first; HA-group HFs last (ADR-0001).
_ORDER = {"sh": 0, "deployer": 1, "cm": 2, "ds": 3, "idx": 4}


@dataclass(frozen=True)
class Server:
    name: str
    host: str
    role: str
    site: str | None = None
    ha_group: str | None = None
    ssh_user: str | None = None
    run_as: str | None = "splunk"
    splunk_home: str = "/data/splunk"
    ssh_options: tuple[str, ...] = ()
    timeout_seconds: int = 900
    btool: bool = True
    local_only_apps: tuple[str, ...] = ()
    # HA member that also runs pull inputs (DB Connect, scripted) from these apps only.
    pull_apps: tuple[str, ...] = ()
    # REST (search heads only, SPEC-002)
    rest_token_env: str | None = None
    rest_token_file: str | None = None
    rest_port: int = 8089
    rest_scheme: str = "https"
    rest_verify_tls: bool = True
    rest_ca_file: str | None = None
    allow_privileged_token: bool = False

    @property
    def rest_enabled(self) -> bool:
        return self.role == "sh" and bool(self.rest_token_env or self.rest_token_file)

    @property
    def order_key(self) -> tuple[int, str]:
        if self.role == "hf":
            return (6 if self.ha_group else 5, self.name)
        return (_ORDER[self.role], self.name)


@dataclass(frozen=True)
class Environment:
    name: str
    servers: tuple[Server, ...]
    vips: frozenset[str] = field(default_factory=frozenset)

    def ordered(self, only: set[str] | None = None) -> list[Server]:
        servers = [s for s in self.servers if not only or s.name in only]
        if only:
            unknown = only - {s.name for s in self.servers}
            if unknown:
                raise EnvironmentError_(f"unknown server(s): {', '.join(sorted(unknown))}")
        return sorted(servers, key=lambda s: s.order_key)


class EnvironmentError_(ValueError):
    pass


_SERVER_KEYS = {
    "name", "host", "role", "site", "ha_group", "ssh_user", "run_as", "splunk_home",
    "ssh_options", "timeout_seconds", "btool", "local_only_apps",
    "rest_token_env", "rest_token_file", "rest_port", "rest_scheme", "rest_verify_tls",
    "rest_ca_file", "allow_privileged_token", "pull_apps",
}
# Per-server only: a token or privilege opt-in in [defaults] would silently apply to HFs.
_SERVER_ONLY_KEYS = {"name", "host", "role", "site", "ha_group", "rest_token_env",
                     "rest_token_file", "allow_privileged_token", "pull_apps"}


def load(path: str | Path) -> Environment:
    data = tomllib.loads(Path(path).read_text())
    name = data.get("name")
    if not name:
        raise EnvironmentError_("environment 'name' is required")
    defaults = data.get("defaults", {})
    unknown = set(defaults) - (_SERVER_KEYS - _SERVER_ONLY_KEYS)
    if unknown:
        raise EnvironmentError_(f"unknown keys in [defaults]: {sorted(unknown)}")

    servers = []
    seen = set()
    for raw in data.get("servers", []):
        unknown = set(raw) - _SERVER_KEYS
        if unknown:
            raise EnvironmentError_(f"server {raw.get('name')!r}: unknown keys {sorted(unknown)}")
        merged = {**defaults, **raw}
        for key in ("name", "host", "role"):
            if not merged.get(key):
                raise EnvironmentError_(f"server entry missing {key!r}: {raw}")
        if merged["role"] not in ROLES:
            raise EnvironmentError_(f"server {merged['name']!r}: role must be one of {ROLES}")
        if merged["role"] != "sh" and (merged.get("rest_token_env") or merged.get("rest_token_file")):
            raise EnvironmentError_(
                f"server {merged['name']!r}: REST is only allowed on search heads (ADR-0001)")
        if merged.get("rest_scheme", "https") not in ("https", "http"):
            raise EnvironmentError_(f"server {merged['name']!r}: rest_scheme must be https or http")
        if merged["name"] in seen:
            raise EnvironmentError_(f"duplicate server name {merged['name']!r}")
        seen.add(merged["name"])
        if merged.get("pull_apps") and merged["role"] != "hf":
            raise EnvironmentError_(f"server {merged['name']!r}: pull_apps is only for heavy forwarders")
        for key in ("ssh_options", "local_only_apps", "pull_apps"):
            if key in merged:
                merged[key] = tuple(merged[key])
        if merged.get("run_as") == "":
            merged["run_as"] = None
        servers.append(Server(**merged))

    env = Environment(name=name, servers=tuple(servers), vips=frozenset(data.get("vips", [])))
    for server in env.servers:
        if is_vip(server.host, env.vips):
            raise EnvironmentError_(
                f"server {server.name!r} host {server.host!r} is a VIP; use the node's own address"
            )
    return env


def _resolve(host: str) -> set[str]:
    try:
        return {info[4][0] for info in socket.getaddrinfo(host, None)}
    except OSError:
        return set()


def is_vip(host: str, vips: frozenset[str], resolver=_resolve) -> bool:
    if host in vips:
        return True
    vip_addrs = set()
    for vip in vips:
        vip_addrs |= resolver(vip) or {vip}
    return bool(resolver(host) & vip_addrs)
