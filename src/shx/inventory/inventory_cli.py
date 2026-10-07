"""shx-inventory: what is installed and what collects data, per server.

    shx-inventory snapshots/<env>/<run_id> [--env environments/<env>.toml] [--out DIR]

Writes apps.csv, inputs.csv, inventory.md and suggested_env.toml (HA groups and VIPs from
keepalived, pull_apps from the inputs found on HA members). Run it after the first
collection, review the suggestions, add them to the environment file, then rerun
shx-compare / shx-findings with --env; no recollection is needed.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

from shx.inventory.apps import inventory_rows
from shx.inventory.cli import _table, write_csv
from shx.inventory.inputs import input_rows, keepalived_instances, suggest, suggestions_toml
from shx.rules.context import RunContext
from shx.snapshot import load_run

def markdown(ctx, rows, missing, instances, toml) -> str:
    counts = defaultdict(Counter)
    for r in rows:
        if r["enabled"]:
            counts[r["server"]][r["kind"]] += 1
    vrrp = defaultdict(list)
    for i in instances:
        vrrp[i.server].append(f"{i.name} {i.state} {'/'.join(i.vips)}".strip())

    lines = [f"# Inventory — {ctx.run.get('environment', '')} / {ctx.run.get('run_id', '')}", ""]
    lines += _table(["Server", "Role", "Site", "HA group", "Apps", "Push", "Pull", "Local", "Keepalived"],
                    [[s.name, s.role_label, s.site or "", s.ha_group or "", str(len(s.apps)),
                      str(counts[s.name]["push"]), str(counts[s.name]["pull"]), str(counts[s.name]["local"]),
                      "; ".join(vrrp.get(s.name, []))] for s in ctx.servers()])
    if missing:
        lines += ["", f"No btool inputs for: {', '.join(missing)} (inputs unknown there)."]
    lines += ["", "## Suggested environment settings", "", "```toml", toml.rstrip(), "```"]

    for kind, title in (("pull", "Pull inputs (scripted, DB Connect, modular/API)"),
                        ("push", "Push inputs (syslog, HEC, splunktcp)")):
        lines += ["", f"## {title}", ""]
        kind_rows = [r for r in rows if r["kind"] == kind]
        if not kind_rows:
            lines.append("None found.")
            continue
        lines += _table(["Server", "App", "Stanza", "Enabled", "Sourcetype", "Index", "Interval", "Path exists"],
                        [[r["server"], r["app"], r["stanza"], "yes" if r["enabled"] else "no", r["sourcetype"],
                          r["index"], r["interval"], "" if r["path_exists"] == "" else str(r["path_exists"])]
                         for r in kind_rows])

    lines += ["", "## Local inputs (monitor, Windows, …) per app", ""]
    local = Counter((r["server"], r["app"]) for r in rows if r["kind"] == "local" and r["enabled"])
    lines += _table(["Server", "App", "Enabled inputs"], [[s, a, str(n)] for (s, a), n in sorted(local.items())]) \
        if local else ["None found."]
    lines += ["", "Full detail in inputs.csv and apps.csv."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shx-inventory", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run_dir")
    parser.add_argument("--env", help="environment file whose ha_group/pull_apps/site override run.json")
    parser.add_argument("--out", help="output directory (default: <run_dir>/reports)")
    args = parser.parse_args(argv)

    ctx = RunContext(args.run_dir, load_run(args.run_dir, args.env))
    if not ctx.snapshots:
        print("error: no successful snapshots in run", file=sys.stderr)
        return 2
    rows, missing = input_rows(ctx)
    instances = keepalived_instances(ctx)
    sugg = suggest(ctx, rows, instances)
    toml = suggestions_toml(sugg)

    out = Path(args.out) if args.out else Path(args.run_dir) / "reports"
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out / "apps.csv", inventory_rows(ctx.snapshots))
    write_csv(out / "inputs.csv", rows)
    (out / "suggested_env.toml").write_text(toml)
    (out / "inventory.md").write_text(markdown(ctx, rows, missing, instances, toml))
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
