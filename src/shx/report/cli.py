"""shx-report: three tables for deciding the cleanup, from one collection run.

    shx-report snapshots/<env>/<run_id> [--env environments/<env>.toml] [--out DIR]

  apps.csv             every app x location (server/root): version, variant letter, +local
  app_settings.csv     for apps whose copies differ: the conf keys and files that differ
  system_settings.csv  non-stock instance settings (server, web, outputs, ...) per server, with source
  indexes.csv          indexes per site: where defined, settings, size/time range, differences
  report.md            short summary of the above

Read-only: nothing is generated for deployment and nothing is sent anywhere.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from shx.report.apps import app_settings_table, apps_table
from shx.report.common import write_csv
from shx.report.indexes import indexes_table
from shx.report.system import system_table
from shx.rules.context import RunContext
from shx.snapshot import load_run


def summary(ctx, apps, app_settings, system, indexes) -> str:
    multi = [r for r in apps if r["variants"] > 1]
    lines = [f"# Report — {ctx.run.get('environment', '')} / {ctx.run.get('run_id', '')}", "",
             f"Servers: {', '.join(s.name + ' (' + s.role_label + ')' for s in ctx.servers())}", "",
             "## Apps", "",
             f"- {len(apps)} apps; {len(multi)} exist in more than one variant "
             f"({len({r['app'] for r in app_settings})} with setting/file differences in app_settings.csv).",
             f"- {sum(1 for r in apps if r['with_local'])} apps carry local/ somewhere."]
    for r in sorted(multi, key=lambda r: -r["variants"])[:15]:
        lines.append(f"  - {r['app']}: {r['variants']} variants, versions {r['versions']}")
    differing = [r for r in system if r["differs"]]
    lines += ["", "## Instance settings", "",
              f"- {len(system)} non-stock settings; {len(differing)} differ between servers "
              "(system_settings.csv, column `differs`)."]
    only = [r for r in indexes if r["only_in"]]
    diff_idx = [r for r in indexes if r["differs"]]
    lines += ["", "## Indexes", "",
              f"- {len(indexes)} indexes; {len(only)} exist on one site only; "
              f"{len(diff_idx)} are defined differently between sites."]
    for r in only[:30]:
        lines.append(f"  - {r['index']}: only in {r['only_in']}")
    for r in diff_idx[:30]:
        lines.append(f"  - {r['index']}: {r['differs']}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shx-report", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run_dir")
    parser.add_argument("--env", help="environment file whose role/site/ha_group override run.json")
    parser.add_argument("--out", help="output directory (default: <run_dir>/reports)")
    args = parser.parse_args(argv)

    ctx = RunContext(args.run_dir, load_run(args.run_dir, args.env))
    if not ctx.snapshots:
        print("error: no successful snapshots in run", file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else Path(args.run_dir) / "reports"
    out.mkdir(parents=True, exist_ok=True)

    apps, apps_cols = apps_table(ctx)
    app_settings, settings_cols = app_settings_table(ctx)
    system, system_cols = system_table(ctx)
    indexes, index_cols = indexes_table(ctx)
    write_csv(out / "apps.csv", apps, apps_cols)
    write_csv(out / "app_settings.csv", app_settings, settings_cols)
    write_csv(out / "system_settings.csv", system, system_cols)
    write_csv(out / "indexes.csv", indexes, index_cols)
    (out / "report.md").write_text(summary(ctx, apps, app_settings, system, indexes))
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
