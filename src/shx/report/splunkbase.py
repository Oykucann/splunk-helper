"""Latest Splunkbase release per app, looked up by app folder name from the engineer's machine.

Only the app name is sent. Results are cached next to the report so reruns stay offline.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

API = "https://splunkbase.splunk.com/api/v1/app/?appid={appid}&include=releases"

# Splunk's own apps: not on Splunkbase as separate downloads.
BUILTIN = {
    "search", "launcher", "learned", "legacy", "sample_app", "user-prefs", "appsbrowser",
    "introspection_generator_addon", "splunk_archiver", "splunk_instrumentation",
    "splunk_monitoring_console", "splunk_secure_gateway", "splunk_rapid_diag",
    "splunk_metrics_workspace", "splunk_httpinput", "splunk_internal_metrics", "splunk_gdi",
    "splunk_assist", "splunk-dashboard-studio", "python_upgrade_readiness_app", "journald_input",
    "alert_logevent", "alert_webhook", "SplunkForwarder", "SplunkLightForwarder",
    "SplunkDeploymentServerConfig", "splunk_ingest_actions", "splunk-visual-exporter", "framework",
    "gettingstarted", "splunk_essentials_9_0", "dmc", "_cluster", "_cluster_admin",
}


def _version_key(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def lookup(appid: str, opener=urllib.request.urlopen, timeout: float = 10.0) -> dict | None:
    url = API.format(appid=urllib.parse.quote(appid))
    with opener(url, timeout=timeout) as resp:
        data = json.loads(resp.read())
    for result in data.get("results", []):
        if result.get("appid") != appid:
            continue
        releases = [r.get("title") or r.get("name") for r in result.get("releases") or []]
        releases = [r for r in releases if r]
        if not releases:
            return None
        return {"latest": max(releases, key=_version_key), "url": result.get("path")}
    return None


def latest_versions(app_names: list[str], cache_file: Path, offline: bool = False,
                    lookup_fn=lookup) -> dict[str, dict | None]:
    cache: dict[str, dict | None] = {}
    if cache_file.exists():
        cache = json.loads(cache_file.read_text())
    wanted = [a for a in app_names if a not in BUILTIN and a not in cache]
    if wanted and not offline:
        def safe(name):
            try:
                return name, lookup_fn(name)
            except Exception:  # network error: leave uncached, retried next time
                return name, "error"
        with ThreadPoolExecutor(max_workers=8) as pool:
            for name, result in pool.map(safe, wanted):
                if result != "error":
                    cache[name] = result
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps(cache, indent=1, sort_keys=True))
    return {a: cache.get(a) for a in app_names}
