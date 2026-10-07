"""shx-findings: run every rule over one collection run.

    shx-findings snapshots/<env>/<run_id> [--out DIR]

Writes findings.json, findings.csv and findings.md. Rules that could not run are listed
as not applicable / insufficient data, never as passed.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

from shx.rules import data, ha, inputs, platform, retention  # noqa: F401  (register rules)
from shx.rules.base import REGISTRY, SEVERITIES, Finding, RuleResult, run_rules
from shx.rules.context import RunContext
from shx.snapshot import load_run

CATEGORY_ORDER = ["prod-risk", "data-integrity", "target-readiness", "retention", "drift",
                  "shc-migration", "dead-input", "broken-input", "capacity", "security"]
MAX_EVIDENCE_IN_MD = 8


def _sort_key(f: Finding):
    return (SEVERITIES.index(f.severity), f.confidence != "proven",
            CATEGORY_ORDER.index(f.category) if f.category in CATEGORY_ORDER else 99, f.rule, f.target)


def _cell(text) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def markdown(results: list[RuleResult], findings: list[Finding], run: dict) -> str:
    counts = Counter(f.severity for f in findings)
    lines = [f"# Findings — {run.get('environment', '')} / {run.get('run_id', '')}", "",
             " · ".join(f"**{s}**: {counts[s]}" for s in SEVERITIES), "",
             "Confidence: **proven** = backed by configuration or log evidence; **suspected** = "
             "inferred, verify before acting.", "", "## Rules", ""]
    lines += ["| Rule | Title | Status | Findings | Note |", "|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r.rule} | {_cell(r.title)} | {r.status} | {len(r.findings)} | {_cell(r.note)} |")
    for sev in SEVERITIES:
        sev_findings = [f for f in findings if f.severity == sev]
        if not sev_findings:
            continue
        lines += ["", f"## {sev.capitalize()} ({len(sev_findings)})"]
        for f in sev_findings:
            where = ", ".join(f.sites + f.servers)
            lines += ["", f"### [{f.rule}] {f.title}", "",
                      f"`{f.id}` · {f.category} · {f.confidence}" + (f" · {where}" if where else ""), ""]
            for e in f.evidence[:MAX_EVIDENCE_IN_MD]:
                parts = [p for p in (e.server, e.path and f"{e.path}" + (f":{e.line}" if e.line else ""),
                                     e.stanza and f"[{e.stanza}]", e.key and f"{e.key}" + (f" = {e.value}" if e.value else ""),
                                     e.search and f"search:{e.search}", e.detail) if p]
                lines.append(f"- {_cell(' · '.join(parts))}")
            if len(f.evidence) > MAX_EVIDENCE_IN_MD:
                lines.append(f"- … {len(f.evidence) - MAX_EVIDENCE_IN_MD} more in findings.json")
            if f.recommendation:
                lines += ["", f"→ {f.recommendation}"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shx-findings", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run_dir")
    parser.add_argument("--out", help="output directory (default: <run_dir>/reports)")
    parser.add_argument("--env", help="environment file whose ha_group/pull_apps/site override run.json")
    args = parser.parse_args(argv)

    ctx = RunContext(args.run_dir, load_run(args.run_dir, args.env))
    if not ctx.snapshots and not ctx.rest:
        print("error: nothing collected in this run", file=sys.stderr)
        return 2
    results = run_rules(ctx, REGISTRY)
    findings = sorted((f for r in results for f in r.findings), key=_sort_key)

    out = Path(args.out) if args.out else Path(args.run_dir) / "reports"
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps({
        "environment": ctx.run.get("environment"), "run_id": ctx.run.get("run_id"),
        "rules": [{"rule": r.rule, "title": r.title, "status": r.status, "note": r.note,
                   "findings": len(r.findings)} for r in results],
        "findings": [f.to_dict() for f in findings],
    }, indent=1))
    with (out / "findings.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "severity", "confidence", "category", "rule", "title", "sites", "servers",
                    "recommendation"])
        for f in findings:
            w.writerow([f.id, f.severity, f.confidence, f.category, f.rule, f.title, " ".join(f.sites),
                        " ".join(f.servers), f.recommendation])
    (out / "findings.md").write_text(markdown(results, findings, ctx.run))
    errors = [r for r in results if r.status == "error"]
    for r in errors:
        print(f"rule {r.rule} failed: {r.note}", file=sys.stderr)
    print(out)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
