"""Read-only Splunk REST client for search heads (SPEC-002).

Only GET on /services and /servicesNS, and POST of oneshot searches that pass the SPL guard.
"""

from __future__ import annotations

import base64
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

SEARCH_PATH = "/services/search/jobs"
MAX_RESPONSE_BYTES = 64 * 1024 * 1024

# Commands that write, send, execute or expand to arbitrary searches.
DENIED_COMMANDS = frozenset({
    "collect", "outputlookup", "outputcsv", "outputtext", "delete", "sendemail", "sendalert",
    "script", "run", "runshellscript", "map", "savedsearch", "tscollect", "mcollect",
    "meventcollect", "summaryindex", "dump", "sichart", "sirare", "sistats", "sitimechart",
    "sitop", "deletefromkvstore", "ldapmodify", "makecontinuous_writer",
})
# Capabilities that mean the token can change things; such a token is refused (SPEC-002).
PRIVILEGED_CAPABILITIES = frozenset({
    "admin_all_objects", "delete_by_keyword", "edit_server", "edit_user", "edit_roles",
    "edit_tcp", "edit_udp", "edit_monitor", "edit_scripted", "edit_token_http",
    "edit_deployment_server", "edit_indexer_cluster", "edit_search_head_clustering",
    "change_authentication", "restart_splunkd", "install_apps", "edit_local_apps",
    "indexes_edit", "edit_forwarders", "edit_kvstore", "run_collect", "run_mcollect",
    "run_sendalert", "schedule_search", "output_file",
})


class GuardError(ValueError):
    """Raised before a request that would violate the read-only contract."""


class RestError(RuntimeError):
    pass


def _split_pipeline(spl: str) -> list[str]:
    """Split on pipes outside quotes (subsearch pipes included)."""
    parts, buf, quote = [], [], None
    i = 0
    while i < len(spl):
        ch = spl[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(spl):
                buf.append(spl[i + 1])
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch == "|":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def check_spl(spl: str) -> None:
    if "`" in spl:
        raise GuardError("macros are not allowed (they can expand to any command)")
    for segment in _split_pipeline(spl):
        words = segment.strip().lstrip("[").split()
        if words and words[0].lower() in DENIED_COMMANDS:
            raise GuardError(f"command {words[0]!r} is not allowed")


def check_request(method: str, path: str, form: dict | None) -> None:
    if not (path.startswith("/services/") or path.startswith("/servicesNS/")):
        raise GuardError(f"path {path!r} is outside /services")
    if method == "GET":
        return
    if method != "POST" or path.rstrip("/") != SEARCH_PATH:
        raise GuardError(f"{method} {path} is not allowed")
    if not form or form.get("exec_mode") != "oneshot" or "search" not in form:
        raise GuardError("only oneshot searches may be POSTed")
    check_spl(form["search"])


_SECRET_IN_TEXT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)"
    r"(\s*[:=]\s*(?:(?:bearer|basic|splunk)\s+)?|\s+(?:bearer|basic|splunk)\s+)(\S+)")


def mask_text(text: str) -> str:
    return _SECRET_IN_TEXT_RE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", text)


@dataclass
class RestClient:
    base_url: str               # e.g. https://10.0.1.10:8089
    token: str = ""             # bearer token, or the password when `username` is set
    verify_tls: bool = True
    ca_file: str | None = None
    timeout: float = 300.0
    opener: object = None       # injectable for tests
    username: str | None = None  # set -> HTTP basic auth with `token` as the password

    def _authorization(self) -> str:
        if self.username:
            raw = f"{self.username}:{self.token}".encode()
            return "Basic " + base64.b64encode(raw).decode()
        return f"Bearer {self.token}"

    def __repr__(self) -> str:  # never print credentials
        return f"RestClient({self.base_url!r}, user={self.username!r})"

    def _context(self):
        if not self.base_url.startswith("https"):
            return None
        if not self.verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return ssl.create_default_context(cafile=self.ca_file)

    def request(self, method: str, path: str, params: dict | None = None,
                form: dict | None = None) -> dict:
        check_request(method, path, form)
        query = {"output_mode": "json", **(params or {})}
        url = f"{self.base_url.rstrip('/')}{path}?{urllib.parse.urlencode(query)}"
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", self._authorization())
        if data is not None:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        open_ = self.opener or urllib.request.urlopen
        try:
            with open_(req, timeout=self.timeout, context=self._context()) as resp:
                body = resp.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            snippet = mask_text(exc.read(1024).decode(errors="replace"))
            raise RestError(f"HTTP {exc.code} for {method} {path}: {snippet}") from None
        except urllib.error.URLError as exc:
            raise RestError(f"{method} {path}: {exc.reason}") from None
        if len(body) > MAX_RESPONSE_BYTES:
            raise RestError(f"response for {path} exceeds {MAX_RESPONSE_BYTES} bytes")
        return json.loads(body or b"{}")

    def get(self, path: str, **params) -> dict:
        return self.request("GET", path, params={"count": 0, **params})

    def oneshot(self, spl: str, earliest: str | None = None, latest: str = "now") -> dict:
        form = {"search": spl if spl.lstrip().startswith("|") else f"search {spl}",
                "exec_mode": "oneshot", "count": "0", "output_mode": "json"}
        if earliest:
            form["earliest_time"] = earliest
            form["latest_time"] = latest
        started = time.monotonic()
        payload = self.request("POST", SEARCH_PATH, form=form)
        payload["_seconds"] = round(time.monotonic() - started, 2)
        return payload

    def current_context(self) -> dict:
        entry = self.get("/services/authentication/current-context")["entry"][0]["content"]
        return {"username": entry.get("username"), "roles": entry.get("roles", []),
                "capabilities": sorted(entry.get("capabilities", []))}


def privileged(capabilities) -> list[str]:
    return sorted(set(capabilities) & PRIVILEGED_CAPABILITIES)
