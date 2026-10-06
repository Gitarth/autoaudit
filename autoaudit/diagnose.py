"""
Why are real vulnerabilities missed? Find rule gaps from labelled misses.

For every CWE, compare the files of real vulnerabilities the scanner MISSED with
the ones it FOUND, and rank the calls that are typical of the misses but not
matched by any source, sink or sanitizer pattern of the rules for that CWE.
That is exactly how the `getHeaderNames` and `JdbcTemplate.query` gaps were
found by hand; this makes it a command.

Ground truth comes from OWASP Benchmark's expectedresults CSV or from a
generic CSV `path,cwe,real` (one row per file and CWE).
"""

from __future__ import annotations

import csv
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from .alerts import Alert
from .codeindex import CodeIndex
from .evaluate import BENCH_TEST


@dataclass
class Truth:
    key: str  # file path (generic) or Benchmark test name
    cwe: str
    real: bool


def read_truth(path: Path) -> list[Truth]:
    out = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            cwe = row["cwe"].strip().upper()
            cwe = cwe if cwe.startswith("CWE-") else f"CWE-{int(cwe)}"
            out.append(Truth(row["path"].strip(), cwe, row["real"].strip().lower() in ("true", "1", "yes")))
    return out


def owasp_truth(expected: dict[str, tuple[str, bool]]) -> list[Truth]:
    return [Truth(name, cwe, real) for name, (cwe, real) in expected.items()]


def _key(alert_path: str, owasp: bool) -> str:
    if owasp:
        m = BENCH_TEST.search(alert_path)
        return m.group(1) if m else alert_path
    return alert_path


def _patterns(spec: dict, cwe: str) -> list[re.Pattern]:
    pats = []
    for r in spec.get("rules", []):
        if r.get("cwe", "").upper() != cwe:
            continue
        for item in r.get("sources", []) + r.get("sinks", []) + r.get("sanitizers", []):
            try:
                pats.append(re.compile(item["pattern"]))
            except re.error:
                pass
    return pats


def _covered(name: str, pats: list[re.Pattern]) -> bool:
    return any(p.fullmatch(name) for p in pats)


def diagnose(
    alerts: list[Alert],
    truth: list[Truth],
    index: CodeIndex,
    spec: dict,
    file_of: dict[str, str] | None = None,
    top: int = 15,
    min_share: float = 0.1,
    min_lift: float = 1.5,
) -> dict:
    """`file_of` maps a truth key to its path in `index` (needed for Benchmark test names)."""
    owasp = file_of is not None
    flagged: dict[str, set[str]] = defaultdict(set)
    for a in alerts:
        for cwe in a.cwes:
            flagged[cwe].add(_key(a.path, owasp))

    calls_in: dict[str, set[str]] = {}

    def calls(key: str) -> set[str]:
        if key not in calls_in:
            rel = file_of.get(key) if owasp else key
            calls_in[key] = {c.callee for c in index.callers_in(rel)} if rel else set()
        return calls_in[key]

    report = {}
    for cwe in sorted({t.cwe for t in truth} & set(flagged), key=lambda c: int(c[4:])):
        cases = [t for t in truth if t.cwe == cwe and t.real]
        missed = [t.key for t in cases if t.key not in flagged[cwe]]
        found = [t.key for t in cases if t.key in flagged[cwe]]
        if not missed:
            report[cwe] = {"real": len(cases), "missed": 0, "candidates": []}
            continue
        in_missed = Counter(n for k in missed for n in calls(k))
        in_found = Counter(n for k in found for n in calls(k))
        pats = _patterns(spec, cwe)
        cands = []
        for name, m in in_missed.items():
            share = m / len(missed)
            if m < 2 or share < min_share or _covered(name, pats):
                continue
            found_share = in_found[name] / len(found) if found else 0.0
            lift = share / (found_share + 1 / (len(found) + 1))
            if lift < min_lift:
                continue  # no more typical of misses than of hits: not an explanation
            cands.append(
                {
                    "call": name,
                    "missed_files": m,
                    "missed_share": round(share, 3),
                    "found_share": round(found_share, 3),
                    "lift": round(lift, 2),
                }
            )
        cands.sort(key=lambda c: (-c["lift"], -c["missed_files"]))
        report[cwe] = {
            "real": len(cases),
            "missed": len(missed),
            "candidates": cands[:top],
            "examples": sorted(missed)[:5],
        }
    return report


def format_report(report: dict) -> str:
    lines = []
    for cwe, r in report.items():
        lines.append(f"{cwe}: {r['missed']} of {r['real']} real vulnerabilities missed")
        for c in r["candidates"]:
            lines.append(
                f"    {c['call']:<28} in {c['missed_files']:>4} missed files "
                f"({c['missed_share']:.0%}) vs {c['found_share']:.0%} of found  lift {c['lift']}"
            )
        if r["missed"] and not r["candidates"]:
            lines.append(
                "    no uncovered call stands out: the flow is probably broken mid-path "
                "(try library summaries or the sink sweep)"
            )
    return "\n".join(lines)
