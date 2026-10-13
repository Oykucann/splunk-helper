"""Which app copies differ between servers (used to pick phase-2 detail and by the report)."""

from __future__ import annotations

from collections import defaultdict


def signature(app: dict) -> tuple:
    """Copies with the same signature are identical: same version, shipped content and local/."""
    return (app.get("version"), app.get("content_fp"), app.get("local_fp"))


def differing_apps(summaries: dict[str, dict]) -> dict[str, list[str]]:
    """server -> ["root/name", ...] for every copy of an app whose copies are not all identical."""
    copies = defaultdict(list)  # app name -> [(server, app dict)]
    for server, summary in summaries.items():
        for app in summary.get("apps", []):
            copies[app["name"]].append((server, app))
    wanted = defaultdict(list)
    for name, items in copies.items():
        if len(items) > 1 and len({signature(a) for _s, a in items}) > 1:
            for server, app in items:
                wanted[server].append(f"{app['root']}/{app['name']}")
    return {s: sorted(v) for s, v in wanted.items()}
