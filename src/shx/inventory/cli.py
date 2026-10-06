"""shx-compare: app and effective-config comparison for one collection run.

    shx-compare snapshots/<env>/<run_id> [--out DIR]

Writes apps.csv (one row per server x app), app_differences.csv, conf_differences.csv
and comparison_report.md.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

from shx.conf.compare import ConfDifference
from shx.conf.compare import compare_all as compare_confs
from shx.inventory.apps import Difference, compare_all, inventory_rows
from shx.snapshot import load_run

LEVEL_TITLES = {
    "ha_group": "HA group members (must be identical)",
    "site": "Same role within a site",
    "cross_site": "Same role across sites",
}
SEVERITY_ORDER = {"high": 0, "medium": 1, "decision": 2, "info": 3}
MAX_CELL = 80


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("")
        return
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _values(values: dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in values.items())


def app_rows(diffs: list[Difference]) -> list[dict]:
    return [{"severity": d.severity, "level": d.level, "scope": d.scope, "root": d.root,
             "app": d.app, "kind": d.kind, "values": _values(d.values)} for d in diffs]


def conf_rows(diffs: list[ConfDifference]) -> list[dict]:
    return [{"severity": d.severity, "level": d.level, "scope": d.scope, "conf": d.conf,
             "stanza": d.stanza, "key": d.key, "expect": d.expect, "values": _values(d.values),
             "note": d.note} for d in diffs]


def _cell(value: str) -> str:
    value = value.replace("|", "\\|").replace("\n", " ")
    return value if len(value) <= MAX_CELL else value[:MAX_CELL - 1] + "…"


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    return ["| " + " | ".join(header) + " |", "|" + "---|" * len(header),
            *("| " + " | ".join(_cell(c) for c in r) + " |" for r in rows)]


def app_section(diffs: list[Difference]) -> list[str]:
    lines = ["", "# Apps"]
    for level, title in LEVEL_TITLES.items():
        level_diffs = [d for d in diffs if d.level == level]
        lines += ["", f"## {title}", ""]
        if not level_diffs:
            lines.append("No differences.")
            continue
        counts = Counter(d.kind for d in level_diffs)
        lines.append(", ".join(f"{k}: {n}" for k, n in sorted(counts.items())))
        for scope in sorted({d.scope for d in level_diffs}):
            scoped = sorted((d for d in level_diffs if d.scope == scope),
                            key=lambda d: (d.kind != "version", d.root, d.app, d.kind))
            members = sorted({m for d in scoped for m in d.values})
            lines += ["", f"### {scope}", ""]
            lines += _table(["Root", "App", "Difference", *members],
                            [[d.root, d.app, d.kind, *(d.values.get(m, "") for m in members)]
                             for d in scoped])
    return lines


def conf_section(diffs: list[ConfDifference]) -> list[str]:
    lines = ["", "# Configuration"]
    for level, title in LEVEL_TITLES.items():
        level_diffs = [d for d in diffs if d.level == level]
        lines += ["", f"## {title}", ""]
        if not level_diffs:
            lines.append("No differences.")
            continue
        counts = Counter(d.severity for d in level_diffs)
        lines.append(", ".join(f"{k}: {counts[k]}" for k in SEVERITY_ORDER if counts[k]))
        for scope in sorted({d.scope for d in level_diffs}):
            scoped = sorted((d for d in level_diffs if d.scope == scope),
                            key=lambda d: (SEVERITY_ORDER[d.severity], d.conf, d.stanza, d.key))
            members = sorted({m for d in scoped for m in d.values})
            lines += ["", f"### {scope}", ""]
            lines += _table(["Severity", "Conf", "Stanza", "Key", *members],
                            [[d.severity, d.conf, d.stanza, d.key, *(d.values.get(m, "") for m in members)]
                             for d in scoped])
    return lines


def markdown(snapshots, app_diffs: list[Difference], conf_diffs: list[ConfDifference]) -> str:
    lines = ["# Environment comparison", ""]
    lines += _table(["Server", "Role", "Site", "HA group", "Apps", "Splunk"],
                    [[s.name, s.role, s.site or "", s.ha_group or "", str(len(s.apps)),
                      s.manifest.get("splunk_version") or ""] for s in snapshots])
    lines += ["", "Severity: **high** = blocks the target or breaks failover; **decision** = "
              "expected to differ between independent sites today, must be unified for the "
              "multisite target. Secret fingerprints are comparable only within one run."]
    lines += conf_section(conf_diffs)
    lines += app_section(app_diffs)
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shx-compare", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run_dir")
    parser.add_argument("--out", help="output directory (default: <run_dir>/reports)")
    args = parser.parse_args(argv)

    snapshots = load_run(args.run_dir)
    if not snapshots:
        print("error: no successful snapshots in run", file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else Path(args.run_dir) / "reports"
    out.mkdir(parents=True, exist_ok=True)
    app_diffs = compare_all(snapshots)
    conf_diffs = compare_confs(snapshots)
    write_csv(out / "apps.csv", inventory_rows(snapshots))
    write_csv(out / "app_differences.csv", app_rows(app_diffs))
    write_csv(out / "conf_differences.csv", conf_rows(conf_diffs))
    (out / "comparison_report.md").write_text(markdown(snapshots, app_diffs, conf_diffs))
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
