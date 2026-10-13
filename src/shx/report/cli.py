"""shx-report: one HTML report from one collection run.

    shx-report snapshots/<env>/<run_id> [--env environments/<env>.toml] [--offline]

Writes <run_dir>/report.html: servers and Splunk service, apps per server with differences,
latest Splunkbase versions, and non-default btool settings (server, web, ...).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from shx.report import splunkbase
from shx.report.html import render
from shx.report.model import build


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shx-report", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run_dir")
    parser.add_argument("--env", help="environment file whose role/site labels override run.json")
    parser.add_argument("--offline", action="store_true", help="do not query Splunkbase")
    parser.add_argument("--out", help="output file (default: <run_dir>/report.html)")
    args = parser.parse_args(argv)

    report = build(args.run_dir, args.env)
    if not report.server_names:
        print("error: no successful snapshots in this run", file=sys.stderr)
        return 2
    latest = splunkbase.latest_versions([a.name for a in report.apps],
                                        Path(args.run_dir) / "splunkbase.json", offline=args.offline)
    for app in report.apps:
        hit = latest.get(app.name)
        if hit:
            app.latest, app.url = hit["latest"], hit.get("url")
    out = Path(args.out) if args.out else Path(args.run_dir) / "report.html"
    out.write_text(render(report), encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
