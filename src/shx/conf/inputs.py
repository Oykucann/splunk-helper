"""Input classification shared by comparisons and rules."""

from __future__ import annotations

# Data sent to Splunk: must be identical on every member of an HA group.
PUSH_SCHEMES = {"udp", "tcp", "tcp-ssl", "splunktcp", "splunktcp-ssl", "http", "splunktcp-token"}
# Local collection; neither push nor pull for HA purposes.
NEUTRAL_SCHEMES = {"monitor", "batch", "fschange", "fifo", "WinEventLog", "perfmon", "admon",
                   "WinRegMon", "WinHostMon", "WinNetMon", "WinPrintMon", "journald"}
# Confs that only exist for pull inputs (DB Connect).
PULL_CONFS = ("db_inputs", "db_connections", "identities")


def scheme(stanza: str) -> str | None:
    return stanza.split("://", 1)[0] if "://" in stanza else None


def is_pull_stanza(stanza: str) -> bool:
    """Scripted, modular/API and other fetched inputs (anything not push or local)."""
    s = scheme(stanza)
    return bool(s) and s not in PUSH_SCHEMES and s not in NEUTRAL_SCHEMES


def app_of_source(source: str) -> str | None:
    """etc/apps/<app>/local/x.conf -> <app>; also peer-apps/slave-apps."""
    parts = source.split("/")
    if len(parts) >= 4 and parts[0] == "etc" and parts[1] in ("apps", "peer-apps", "slave-apps"):
        return parts[2]
    return None
