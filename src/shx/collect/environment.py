"""Environment definition (environments/<name>.toml): which servers to read and how to log in."""

from __future__ import annotations

import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path

from shx import _toml

ROLES = ("sh", "deployer", "cm", "ds", "idx", "hf", "uf")
# Collection order: least critical first; HA-group HFs last (ADR-0001).
_ORDER = {"sh": 0, "deployer": 1, "cm": 2, "ds": 3, "idx": 4, "uf": 5}

# Keys from earlier versions; accepted and ignored so old environment files keep working.
_LEGACY_KEYS = {"rest_token_env", "rest_token_file", "rest_port", "rest_scheme", "rest_verify_tls",
                "rest_ca_file", "allow_privileged_token", "pull_apps", "rest_auth", "rest_username",
                "rest_password_env"}


@dataclass(frozen=True)
class Server:
    name: str
    host: str
    role: str
    site: str | None = None
    ha_group: str | None = None
    ssh_user: str | None = None
    ssh_auth: str = "key"            # "key" (agent/~/.ssh/config or ssh_key) | "password" (ssh prompts)
    ssh_key: str | None = None
    # SSH destination template; {host} and {user} (ssh_user) are filled in. Default is
    # "{user}@{host}" or "{host}"; e.g. "me@{user}@{host}@gateway.example.local".
    ssh_destination: str | None = None
    ssh_options: tuple[str, ...] = ()
    run_as: str | None = "splunk"
    splunk_home: str = "/data/splunk"
    # Interpreter for the remote script: "splunk" (splunk cmd python3) or "system" (python3 on
    # the host). Universal forwarders ship no Python, so "uf" defaults to "system".
    python: str | None = None
    timeout_seconds: int = 900
    btool: bool = True
    local_only_apps: tuple[str, ...] = ()
    also_roles: tuple[str, ...] = ()  # e.g. a lab SH that is also the CM

    @property
    def roles(self) -> tuple[str, ...]:
        return (self.role, *self.also_roles)

    @property
    def interpreter(self) -> str:
        return self.python or ("system" if self.role == "uf" else "splunk")

    @property
    def order_key(self) -> tuple[int, str]:
        if self.role == "hf":
            return (7 if self.ha_group else 6, self.name)
        return (_ORDER[self.role], self.name)


@dataclass(frozen=True)
class Environment:
    name: str
    servers: tuple[Server, ...]
    vips: frozenset[str] = field(default_factory=frozenset)
    # App name patterns left out of collection detail and the report (environment-specific).
    exclude_apps: tuple[str, ...] = ()

    def ordered(self, only: set[str] | None = None) -> list[Server]:
        if only:
            unknown = only - {s.name for s in self.servers}
            if unknown:
                raise EnvironmentError_(f"unknown server(s): {', '.join(sorted(unknown))}")
        servers = [s for s in self.servers if not only or s.name in only]
        return sorted(servers, key=lambda s: s.order_key)


class EnvironmentError_(ValueError):
    pass


_SERVER_KEYS = {
    "name", "host", "role", "site", "ha_group", "ssh_user", "ssh_auth", "ssh_key", "ssh_options",
    "run_as", "splunk_home", "python", "timeout_seconds", "btool", "local_only_apps", "also_roles",
    "ssh_destination",
}
_SERVER_ONLY_KEYS = {"name", "host", "role", "site", "ha_group", "also_roles"}


def _drop_legacy(where: str, table: dict) -> dict:
    old = sorted(set(table) & _LEGACY_KEYS)
    if old:
        print(f"note: {where}: ignoring keys no longer used: {', '.join(old)}", file=sys.stderr)
    return {k: v for k, v in table.items() if k not in _LEGACY_KEYS}


def load(path: str | Path) -> Environment:
    data = _toml.loads(Path(path).read_text())
    name = data.get("name")
    if not name:
        raise EnvironmentError_("environment 'name' is required")
    defaults = _drop_legacy("[defaults]", data.get("defaults", {}))
    unknown = set(defaults) - (_SERVER_KEYS - _SERVER_ONLY_KEYS)
    if unknown:
        raise EnvironmentError_(f"unknown keys in [defaults]: {sorted(unknown)}")

    servers, seen = [], set()
    for raw in data.get("servers", []):
        raw = _drop_legacy(f"server {raw.get('name')!r}", raw)
        unknown = set(raw) - _SERVER_KEYS
        if unknown:
            raise EnvironmentError_(f"server {raw.get('name')!r}: unknown keys {sorted(unknown)}")
        m = {**defaults, **raw}
        label = f"server {m.get('name')!r}"
        for key in ("name", "host", "role"):
            if not m.get(key):
                raise EnvironmentError_(f"server entry missing {key!r}: {raw}")
        if m["role"] not in ROLES:
            raise EnvironmentError_(f"{label}: role must be one of {ROLES}")
        if m["name"] in seen:
            raise EnvironmentError_(f"duplicate server name {m['name']!r}")
        seen.add(m["name"])
        if m.get("ssh_auth", "key") not in ("key", "password"):
            raise EnvironmentError_(f"{label}: ssh_auth must be key or password")
        if m.get("ssh_auth") == "password" and "BatchMode=yes" in m.get("ssh_options", []):
            raise EnvironmentError_(f"{label}: remove BatchMode=yes from ssh_options to use ssh_auth = password")
        dest = m.get("ssh_destination")
        if dest is not None and ("{host}" not in dest or ("{user}" in dest and not m.get("ssh_user"))):
            raise EnvironmentError_(f"{label}: ssh_destination needs {{host}} (and ssh_user when it uses {{user}})")
        if m.get("python") not in (None, "splunk", "system"):
            raise EnvironmentError_(f"{label}: python must be splunk or system")
        extra = list(m.get("also_roles", []))
        if any(r not in ROLES for r in extra) or m["role"] in extra or len(set(extra)) != len(extra):
            raise EnvironmentError_(f"{label}: also_roles must be distinct roles from {ROLES}, other than role")
        for key in ("ssh_options", "local_only_apps", "also_roles"):
            if key in m:
                m[key] = tuple(m[key])
        if m.get("run_as") == "":
            m["run_as"] = None
        servers.append(Server(**m))

    exclude = data.get("exclude_apps", [])
    if not isinstance(exclude, list) or not all(isinstance(x, str) for x in exclude):
        raise EnvironmentError_("exclude_apps must be a list of app name patterns")
    env = Environment(name=name, servers=tuple(servers), vips=frozenset(data.get("vips", [])),
                      exclude_apps=tuple(exclude))
    for server in env.servers:
        if is_vip(server.host, env.vips):
            raise EnvironmentError_(f"server {server.name!r} host {server.host!r} is a VIP; use the node's own address")
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
