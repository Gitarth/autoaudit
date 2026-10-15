"""
Build a labeled dataset from audited FPRs and split it without leakage.

Layout written under <out>/:
    findings.jsonl        one row per audited finding
    sources/<sha256>.java each distinct source file, stored once
    summary.json          counts, label balance, conflicting files
    splits/<name>.jsonl + splits/<name>_labels.csv   (after `split`)
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import Path

from .fpr import FPR, sha256

log = logging.getLogger(__name__)

DEFAULT_LABELS = ("Suspicious", "Not an Issue")


def find_fprs(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted(p for p in path.rglob("*.fpr") if p.is_file())


def build(
    fpr_paths: Iterable[Path],
    out: Path,
    labels: Iterable[str] = DEFAULT_LABELS,
    extensions: Iterable[str] = (".java",),
) -> dict:
    labels = set(labels)
    extensions = tuple(e.lower() for e in extensions)
    sources = out / "sources"
    sources.mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []
    per_fpr = []
    missing_source = 0
    for path in fpr_paths:
        try:
            fpr = FPR.open(path)
        except Exception as err:  # corrupt zip, missing audit.fvdl, bad XML
            log.warning("Skipping %s: %s", path, err)
            per_fpr.append({"project": path.stem, "error": str(err)})
            continue
        with fpr:
            per_fpr.append(fpr.stats())
            for f in fpr.analyzed(labels):
                if not f.path.lower().endswith(extensions):
                    continue
                data = fpr.read_source(f.path)
                if data is None:
                    missing_source += 1
                    log.debug("%s: no source for %s", fpr.project, f.path)
                    continue
                f.source_sha = sha256(data)
                target = sources / f"{f.source_sha}.java"
                if not target.exists():
                    target.write_bytes(data)
                rows.append(f.to_dict())
        log.info("%s: %d findings", path.name, per_fpr[-1].get("total", 0))

    with open(out / "findings.jsonl", "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")

    summary = summarize(rows)
    summary.update(fprs=per_fpr, findings_without_source=missing_source)
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    return summary


def summarize(rows: list[dict]) -> dict:
    """Counts plus the label-noise signal: files that carry opposite labels."""
    file_labels: dict[tuple, set] = defaultdict(set)
    for r in rows:
        file_labels[(r["source_sha"], r["category"])].add(r["analysis"])
    conflicting = sum(1 for v in file_labels.values() if len(v) > 1)
    return {
        "findings": len(rows),
        "projects": len({r["project"] for r in rows}),
        "distinct_files": len({r["source_sha"] for r in rows}),
        "labels": dict(Counter(r["analysis"] for r in rows)),
        "categories": dict(Counter(r["category"] for r in rows).most_common()),
        "file_category_pairs": len(file_labels),
        "file_category_pairs_with_conflicting_labels": conflicting,
    }


def read_rows(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def leakage_groups(rows: list[dict]) -> dict[str, str]:
    """project -> group id. Projects sharing any identical file share a group,
    so copied/vendored/forked code can never straddle train and test."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    first_owner: dict[str, str] = {}
    for r in rows:
        p = find(r["project"])
        owner = first_owner.setdefault(r["source_sha"], r["project"])
        parent[p] = find(owner)
    return {p: find(p) for p in {r["project"] for r in rows}}


def _bucket(key: str, seed: int) -> float:
    h = hashlib.sha256(f"{seed}:{key}".encode()).hexdigest()
    return int(h[:12], 16) / float(1 << 48)


def split(
    rows: list[dict],
    out: Path,
    ratios: tuple[float, float, float] = (0.8, 0.1, 0.1),
    seed: int = 0,
) -> dict:
    """Deterministic, group-aware train/val/test split."""
    if abs(sum(ratios) - 1.0) > 1e-6:
        raise ValueError("split ratios must sum to 1")
    groups = leakage_groups(rows)
    names = ("train", "val", "test")
    cut1, cut2 = ratios[0], ratios[0] + ratios[1]

    def assign(project: str) -> str:
        b = _bucket(groups[project], seed)
        return names[0] if b < cut1 else names[1] if b < cut2 else names[2]

    out.mkdir(parents=True, exist_ok=True)
    parts: dict[str, list[dict]] = {n: [] for n in names}
    for r in rows:
        parts[assign(r["project"])].append(r)

    for name, part in parts.items():
        with open(out / f"{name}.jsonl", "w", encoding="utf-8") as fh:
            for r in part:
                fh.write(json.dumps(r) + "\n")
        with open(out / f"{name}_labels.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["source", "label", "category", "project", "line"])
            for r in part:
                w.writerow(
                    [f"sources/{r['source_sha']}.java", r["analysis"], r["category"], r["project"], r["line"]]
                )

    return {
        n: {
            "findings": len(p),
            "projects": len({r["project"] for r in p}),
            "labels": dict(Counter(r["analysis"] for r in p)),
        }
        for n, p in parts.items()
    }
