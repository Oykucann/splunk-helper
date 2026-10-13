"""Shared helpers for the shx-report tables."""

from __future__ import annotations

import csv
import re
from pathlib import Path

_REDACTED_RE = re.compile(r"<redacted(?::(enc|plain))?(?::([0-9a-f]+))?>")
UNSET = "(unset)"


def label_secrets(values: dict[str, str]) -> dict[str, str]:
    """Replace redaction fingerprints with per-row labels: equal secrets share a label.
    No secret is assumed to be shared; the label only says which cells hold the same value."""
    labels: dict[str, str] = {}
    out = {}
    for col, value in values.items():
        def sub(m):
            kind, fp = m.group(1) or "", m.group(2)
            if not fp:
                return f"secret ({kind})" if kind else "secret"
            labels.setdefault(fp, f"secret#{len(labels) + 1}")
            return f"{labels[fp]} ({kind})" if kind else labels[fp]
        out[col] = _REDACTED_RE.sub(sub, value) if isinstance(value, str) else value
    return out


def server_column(snap) -> str:
    return f"{snap.site or 'no-site'}/{snap.name} ({snap.role_label})"


def write_csv(path: Path, rows: list[dict], columns: list[str] | None = None) -> None:
    columns = columns or (list(rows[0]) if rows else [])
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
