"""
Measure the scanner and the LLM triage against ground truth.

Two label sources:
- OWASP Benchmark's expectedresults-*.csv (test case -> real vulnerability or not, per CWE);
  scored per test case the way the Benchmark scorecard does: TPR, FPR and TPR - FPR.
- A hand-audited CSV `alert_id,label` (label true/false) for real-world alerts.
"""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path

from .alerts import Alert

BENCH_TEST = re.compile(r"(BenchmarkTest\d+)")


def read_owasp_expected(path: Path) -> dict[str, tuple[str, bool]]:
    """test name -> (CWE-<n>, is real vulnerability)."""
    out = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            name, _category, real, cwe = (c.strip() for c in row[:4])
            out[name] = (f"CWE-{int(cwe)}", real.lower() == "true")
    return out


def read_triage(path: Path) -> dict[str, dict]:
    """alert id -> latest successful triage record."""
    out = {}
    if path and path.exists():
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    r = json.loads(line)
                    if r.get("verdict"):
                        out[r["alert_id"]] = r
    return out


def kept(alert: Alert, triage: dict[str, dict] | None, keep_uncertain: bool) -> bool:
    """Does the alert survive triage? (No triage -> every alert is kept.)"""
    if triage is None:
        return True
    r = triage.get(alert.id)
    if r is None:  # not triaged: keep it rather than silently dropping a finding
        return True
    return r["verdict"] == "true_positive" or (keep_uncertain and r["verdict"] == "uncertain")


def score_owasp(
    alerts: list[Alert],
    expected: dict[str, tuple[str, bool]],
    triage: dict[str, dict] | None = None,
    keep_uncertain: bool = True,
) -> dict:
    """Per-CWE Benchmark scorecard over the CWEs the alerts cover."""
    flagged: dict[str, set[str]] = defaultdict(set)  # CWE -> test cases reported
    for a in alerts:
        m = BENCH_TEST.search(a.path)
        if not m or not kept(a, triage, keep_uncertain):
            continue
        for cwe in a.cwes:
            flagged[cwe].add(m.group(1))

    covered = sorted({c for a in alerts for c in a.cwes}, key=lambda c: int(c[4:]))
    rows, totals = {}, defaultdict(int)
    for cwe in covered:
        cases = {t: real for t, (c, real) in expected.items() if c == cwe}
        if not cases:
            continue
        tp = sum(1 for t, real in cases.items() if real and t in flagged[cwe])
        fp = sum(1 for t, real in cases.items() if not real and t in flagged[cwe])
        pos = sum(cases.values())
        neg = len(cases) - pos
        rows[cwe] = _rates(tp, fp, pos, neg)
        for k, v in (("tp", tp), ("fp", fp), ("pos", pos), ("neg", neg)):
            totals[k] += v
    rows["overall"] = _rates(totals["tp"], totals["fp"], totals["pos"], totals["neg"])
    return rows


def _rates(tp: int, fp: int, pos: int, neg: int) -> dict:
    tpr = tp / pos if pos else 0.0
    fpr = fp / neg if neg else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": pos - tp,
        "tn": neg - fp,
        "tpr": round(tpr, 3),
        "fpr": round(fpr, 3),
        "precision": round(prec, 3),
        "score": round(tpr - fpr, 3),
    }


def label_owasp_alerts(alerts: list[Alert], expected: dict[str, tuple[str, bool]]) -> dict[str, bool]:
    """alert id -> real? (only alerts whose CWE matches their test case's CWE)."""
    out = {}
    for a in alerts:
        m = BENCH_TEST.search(a.path)
        if m and m.group(1) in expected:
            cwe, real = expected[m.group(1)]
            if cwe in a.cwes:
                out[a.id] = real
    return out


def read_labels(path: Path) -> dict[str, bool]:
    with open(path, newline="", encoding="utf-8") as fh:
        return {
            r["alert_id"]: r["label"].strip().lower() in ("true", "1", "yes", "tp")
            for r in csv.DictReader(fh)
        }


def score_triage(labels: dict[str, bool], triage: dict[str, dict]) -> dict:
    """Alert-level: how well do verdicts separate real from false alerts?"""
    tp = fp = tn = fn = unc_real = unc_false = 0
    for aid, real in labels.items():
        r = triage.get(aid)
        if r is None:
            continue
        v = r["verdict"]
        if v == "uncertain":
            unc_real += real
            unc_false += not real
        elif v == "true_positive":
            tp += real
            fp += not real
        else:
            fn += real
            tn += not real
    judged = tp + fp + tn + fn
    real_total = tp + fn + unc_real
    false_total = fp + tn + unc_false
    return {
        "labeled_and_triaged": judged + unc_real + unc_false,
        "accuracy": round((tp + tn) / judged, 3) if judged else None,
        "precision": round(tp / (tp + fp), 3) if tp + fp else None,
        "recall_real_kept": round((tp + unc_real) / real_total, 3) if real_total else None,
        "false_alerts_removed": round(tn / false_total, 3) if false_total else None,
        "real_alerts_wrongly_dismissed": fn,
        "uncertain": unc_real + unc_false,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }
