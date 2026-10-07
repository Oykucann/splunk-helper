"""Finding model and rule registry (SPEC-003)."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable

SEVERITIES = ("high", "medium", "low", "info")


@dataclass
class Evidence:
    server: str | None = None
    path: str | None = None
    stanza: str | None = None
    key: str | None = None
    value: str | None = None
    line: int | None = None
    search: str | None = None
    detail: str | None = None

    def compact(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, "")}


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    confidence: str            # proven | suspected
    category: str
    target: str                # what the finding is about, e.g. "site1-push / udp://514"
    servers: list[str] = field(default_factory=list)
    sites: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    recommendation: str = ""

    def __post_init__(self):
        assert self.severity in SEVERITIES, self.severity
        assert self.confidence in ("proven", "suspected"), self.confidence

    @property
    def id(self) -> str:
        # Stable across runs: same rule + same target -> same id, so progress can be diffed.
        return f"{self.rule}-{hashlib.sha256(self.target.encode()).hexdigest()[:10]}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self.id
        d["evidence"] = [e.compact() for e in self.evidence]
        return d


@dataclass
class RuleResult:
    rule: str
    title: str
    status: str                # ran | not_applicable | insufficient_data | error
    findings: list[Finding] = field(default_factory=list)
    note: str = ""


class NotApplicable(Exception):
    """The environment has nothing this rule checks (e.g. no SmartStore index)."""


class InsufficientData(Exception):
    """Inputs the rule needs were not collected (e.g. no REST results)."""


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    fn: Callable[..., Iterable[Finding]]


REGISTRY: list[Rule] = []


def rule(id: str, title: str, category: str):
    def deco(fn):
        REGISTRY.append(Rule(id, title, category, fn))
        return fn
    return deco


def run_rules(ctx, rules: list[Rule] | None = None) -> list[RuleResult]:
    results = []
    for r in rules or REGISTRY:
        try:
            findings = list(r.fn(ctx))
            results.append(RuleResult(r.id, r.title, "ran", findings))
        except NotApplicable as exc:
            results.append(RuleResult(r.id, r.title, "not_applicable", note=str(exc)))
        except InsufficientData as exc:
            results.append(RuleResult(r.id, r.title, "insufficient_data", note=str(exc)))
        except Exception as exc:  # a broken rule must not hide the others
            results.append(RuleResult(r.id, r.title, "error", note=f"{type(exc).__name__}: {exc}"))
    return results
