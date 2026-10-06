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
}


def load(path: str | Path) -> Environment:
    data = tomllib.loads(Path(path).read_text())
    name = data.get("name")
    if not name:
        raise EnvironmentError_("environment 'name' is required")
    defaults = data.get("defaults", {})
    unknown = set(defaults) - (_SERVER_KEYS - {"name", "host", "role", "site", "ha_group"})
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
        if merged["name"] in seen:
            raise EnvironmentError_(f"duplicate server name {merged['name']!r}")
        seen.add(merged["name"])
        for key in ("ssh_options", "local_only_apps"):
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
