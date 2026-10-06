"""Parse `splunk btool <conf> list --debug` output into effective settings with their source."""

from __future__ import annotations

import re
from dataclasses import dataclass

# "<source path><whitespace><conf line>"; the path is absolute on the target host.
_LINE_RE = re.compile(r"^(?P<src>/\S+|[A-Za-z]:\\\S+)\s+(?P<body>.*)$")


@dataclass(frozen=True)
class Setting:
    value: str
    source: str  # path relative to $SPLUNK_HOME, e.g. etc/system/local/server.conf

    @property
    def is_system_default(self) -> bool:
        return self.source.startswith("etc/system/default/")


# stanza -> key -> Setting
EffectiveConf = dict[str, dict[str, Setting]]


def _relative(src: str) -> str:
    src = src.replace("\\", "/")
    idx = src.find("/etc/")
    return src[idx + 1:] if idx != -1 else src


def parse(text: str) -> EffectiveConf:
    conf: EffectiveConf = {}
    stanza = None
    last_key = None
    for raw in text.splitlines():
        m = _LINE_RE.match(raw)
        if not m:
            continue
        source, body = _relative(m.group("src")), m.group("body").rstrip()
        if body.startswith("[") and body.endswith("]"):
            stanza = body[1:-1]
            conf.setdefault(stanza, {})
            last_key = None
        elif stanza is not None and "=" in body:
            key, value = body.split("=", 1)
            last_key = key.strip()
            conf[stanza][last_key] = Setting(value.strip(), source)
        elif stanza is not None and last_key is not None:
            # Continuation of a multi-line value.
            prev = conf[stanza][last_key]
            conf[stanza][last_key] = Setting(prev.value + "\n" + body.strip(), prev.source)
    return conf
