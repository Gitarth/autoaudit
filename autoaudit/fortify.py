"""
Audited Fortify FPRs -> alerts, source trees and labels for learned triage.

For every FPR:
  <out>/<project>/<path>     the source files its findings' traces touch,
                             extracted from the FPR's src-archive
  <alerts>                   one alert per audited finding (tool "fortify"),
                             with Fortify's primary trace as the flow
  <labels>                   alert_id,label: positive verdicts (default
                             Suspicious, Exploitable) -> true, negative
                             (Not an Issue) -> false

Then: `autoaudit ml-dataset --alerts <alerts> --labels <labels> --src-dir <out>
--group project`. Group by project: findings from one codebase share idioms,
so a random split overstates accuracy on a new codebase.

Paths in an FPR are untrusted: absolute paths and paths that climb out of the
project directory are never written.
"""

from __future__ import annotations

import csv
import logging
import posixpath
from collections import Counter
from pathlib import Path

from .alerts import Alert, Step, write_jsonl
from .fpr import FPR

log = logging.getLogger(__name__)

POSITIVE = ("Suspicious", "Exploitable")
NEGATIVE = ("Not an Issue",)

# Fortify category (Type) -> CWE, for the categories common in Java web code.
CWE = {
    "SQL Injection": "CWE-89",
    "Command Injection": "CWE-78",
    "Path Manipulation": "CWE-22",
    "Cross-Site Scripting": "CWE-79",
    "LDAP Injection": "CWE-90",
    "LDAP Manipulation": "CWE-90",
    "XPath Injection": "CWE-643",
    "XML External Entity Injection": "CWE-611",
    "XML Entity Expansion Injection": "CWE-776",
    "XML Injection": "CWE-91",
    "Expression Language Injection": "CWE-917",
    "Server-Side Request Forgery": "CWE-918",
    "Open Redirect": "CWE-601",
    "Header Manipulation": "CWE-113",
    "Log Forging": "CWE-117",
    "Resource Injection": "CWE-99",
    "Setting Manipulation": "CWE-15",
    "Trust Boundary Violation": "CWE-501",
    "Dynamic Code Evaluation": "CWE-95",
    "Code Injection": "CWE-94",
    "Unsafe Reflection": "CWE-470",
    "Dangerous File Inclusion": "CWE-98",
    "Dynamic Code Evaluation: Unsafe Deserialization": "CWE-502",
    "Privacy Violation": "CWE-359",
    "System Information Leak": "CWE-497",
    "Password Management": "CWE-259",
    "Key Management": "CWE-321",
    "Weak Cryptographic Hash": "CWE-328",
    "Weak Encryption": "CWE-327",
    "Insecure Randomness": "CWE-330",
    "Cookie Security": "CWE-614",
    "Null Dereference": "CWE-476",
    "Unreleased Resource": "CWE-772",
    "Denial of Service": "CWE-400",
    "Mass Assignment": "CWE-915",
    "Cross-Site Request Forgery": "CWE-352",
    "Race Condition": "CWE-362",
    "Poor Error Handling": "CWE-703",
    "Often Misused": "CWE-676",
}


def cwe_of(type_: str, subtype: str | None) -> list[str]:
    for key in (f"{type_}: {subtype}" if subtype else None, type_):
        if key and key in CWE:
            return [CWE[key]]
    return []


def safe_rel(path: str) -> str | None:
    """Normalised relative path, or None if it is absolute or leaves the project."""
    p = posixpath.normpath(path.replace("\\", "/"))
    if p.startswith("/") or p == ".." or p.startswith("../") or (len(p) > 1 and p[1] == ":"):
        return None
    return p


def import_fprs(
    fpr_paths: list[Path],
    src_dir: Path,
    alerts_out: Path,
    labels_out: Path,
    positive=POSITIVE,
    negative=NEGATIVE,
) -> dict:
    positive, negative = set(positive), set(negative)
    found: dict[str, Alert] = {}
    labels: dict[str, bool] = {}
    conflicts: set[str] = set()
    stats: Counter = Counter()
    projects: Counter = Counter()
    for path in fpr_paths:
        try:
            fpr = FPR.open(path)
        except Exception as err:  # corrupt zip, missing audit.fvdl, bad XML
            log.warning("Skipping %s: %s", path, err)
            stats["fprs_skipped"] += 1
            continue
        projects[fpr.project] += 1
        project = fpr.project if projects[fpr.project] == 1 else f"{fpr.project}-{projects[fpr.project]}"
        root = src_dir / project
        written: dict[str, bool] = {}

        def extract(rel: str, fpr=fpr, root=root, written=written) -> bool:
            if rel not in written:
                target, data = safe_rel(rel), fpr.read_source(rel)
                written[rel] = target is not None and data is not None
                if written[rel]:
                    out = root / target
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(data)
            return written[rel]

        with fpr:
            stats["fprs"] += 1
            for f in fpr.findings:
                if f.analysis in positive:
                    label = True
                elif f.analysis in negative:
                    label = False
                else:
                    stats["unlabeled_skipped"] += 1
                    continue
                if not f.path or safe_rel(f.path) is None or not extract(f.path):
                    stats["no_source"] += 1
                    continue
                steps = [
                    Step(safe_rel(p), line, None, None)
                    for p, line in f.trace
                    if safe_rel(p) is not None and extract(p)
                ]
                a = Alert(
                    tool="fortify",
                    rule_id=f.category,
                    message=f.category,
                    project=project,
                    path=safe_rel(f.path),
                    line=f.line,
                    function=f.function,
                    severity=str(f.severity) if f.severity is not None else None,
                    cwes=cwe_of(f.type, f.subtype),
                    flow=steps if len(steps) > 1 else [],
                )
                if a.id in found:  # same rule, sink and source as another finding
                    stats["duplicates"] += 1
                    if labels.get(a.id) != label:
                        conflicts.add(a.id)
                    continue
                found[a.id] = a
                labels[a.id] = label
                stats["real" if label else "false"] += 1
    for aid in conflicts:
        labels.pop(aid, None)
    stats["conflicting_labels_dropped"] = len(conflicts)
    alerts_out.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(list(found.values()), alerts_out)
    labels_out.parent.mkdir(parents=True, exist_ok=True)
    with open(labels_out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["alert_id", "label"])
        for aid, lab in labels.items():
            w.writerow([aid, "true" if lab else "false"])
    by_category = Counter(a.rule_id for a in found.values())
    return {
        **stats,
        "alerts": len(found),
        "labeled": len(labels),
        "projects": len(projects),
        "with_flow": sum(1 for a in found.values() if a.flow),
        "top_categories": dict(by_category.most_common(15)),
        "alerts_out": str(alerts_out),
        "labels_out": str(labels_out),
        "src_dir": str(src_dir),
    }
