"""
autoaudit command line.

    autoaudit crawl     search GitHub and download repos pinned to a commit
    autoaudit extract   unzip downloads and list the Maven projects
    autoaudit scan      run Fortify on each Maven project, collect FPRs
    autoaudit stats     per-FPR finding counts by audit verdict
    autoaudit build     audited FPRs -> labeled dataset
    autoaudit split     leakage-safe train/val/test split
    autoaudit metrics   CK code metrics + total LOC
    autoaudit c2v-paths flatten a code2vec .c2v file into one path per line
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
from pathlib import Path

from . import c2v, crawl, dataset, metrics, projects, scan
from .fpr import ANALYSIS_VALUES, FPR


def _projects(data: Path) -> list[tuple[str, Path]]:
    return [(p.relative_to(data / "repos").parts[0], p) for p in projects.maven_projects(data / "repos")]


def cmd_crawl(a):
    rows = crawl.crawl(a.data_dir, a.query, a.limit, a.min_size_kb)
    print(f"{len(rows)} repositories in {a.data_dir / 'repos.csv'}")


def cmd_extract(a):
    stats = projects.extract(a.data_dir / "downloads", a.data_dir / "repos")
    found = _projects(a.data_dir)
    stats["maven_projects"] = len(found)
    print(json.dumps(stats, indent=2))


def cmd_scan(a):
    found = _projects(a.data_dir)
    if a.only:
        found = [p for p in found if p[0] in set(a.only)]
    results = scan.scan_all(found, a.command, a.data_dir, a.fpr_glob, a.timeout)
    counts: dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print(json.dumps(counts, indent=2))


def cmd_stats(a):
    fields = ["project", "total", *sorted(ANALYSIS_VALUES), "Unaudited"]
    w = csv.DictWriter(sys.stdout, fieldnames=fields, restval=0, extrasaction="ignore")
    w.writeheader()
    for path in dataset.find_fprs(a.fprs):
        try:
            with FPR.open(path) as fpr:
                w.writerow(fpr.stats())
        except Exception as err:
            logging.warning("Skipping %s: %s", path, err)


def cmd_build(a):
    summary = dataset.build(dataset.find_fprs(a.fprs), a.out, a.labels)
    summary.pop("fprs")
    print(json.dumps(summary, indent=2))


def cmd_split(a):
    rows = dataset.read_rows(a.out / "findings.jsonl")
    print(json.dumps(dataset.split(rows, a.out / "splits", tuple(a.ratios), a.seed), indent=2))


def cmd_metrics(a):
    out = a.data_dir / "metrics"
    if a.ck_jar:
        metrics.run_ck(a.ck_jar, _projects(a.data_dir), out)
    loc = metrics.total_loc(out)
    print(json.dumps({"projects": len(loc), "total_loc": sum(loc.values())}, indent=2))


def cmd_c2v(a):
    out = a.out or a.c2v_file.with_name(a.c2v_file.name + ".paths.txt")
    print(f"{c2v.extract_paths(a.c2v_file, out)} paths -> {out}")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="autoaudit", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "--data-dir",
        type=Path,
        default=Path(os.environ.get("AUTOAUDIT_DATA_DIR", "data")),
        help="working directory for all artifacts (env: AUTOAUDIT_DATA_DIR)",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("crawl", help="search GitHub and download repositories")
    s.add_argument("--query", default="language:Java webapp")
    s.add_argument("--limit", type=int, default=400, help="max repos (GitHub caps search at 1000)")
    s.add_argument("--min-size-kb", type=int, default=100)
    s.set_defaults(func=cmd_crawl)

    s = sub.add_parser("extract", help="unzip downloads and find Maven projects")
    s.set_defaults(func=cmd_extract)

    s = sub.add_parser("scan", help="run Fortify on each Maven project")
    s.add_argument("--command", required=True, help='template, e.g. "sh mvn-run.sh {project_dir} {name}"')
    s.add_argument("--fpr-glob", default="target/fortify/*.fpr")
    s.add_argument("--timeout", type=int, default=None, help="seconds per project")
    s.add_argument("--only", nargs="*", help="scan only these project names")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("stats", help="finding counts per FPR as CSV")
    s.add_argument("fprs", type=Path, help="an .fpr file or a directory of them")
    s.set_defaults(func=cmd_stats)

    s = sub.add_parser("build", help="build the labeled dataset from audited FPRs")
    s.add_argument("fprs", type=Path, help="an .fpr file or a directory of them")
    s.add_argument("--out", type=Path, default=None, help="default: <data-dir>/dataset")
    s.add_argument("--labels", nargs="+", default=list(dataset.DEFAULT_LABELS))
    s.set_defaults(func=cmd_build)

    s = sub.add_parser("split", help="project-grouped train/val/test split")
    s.add_argument("--out", type=Path, default=None, help="dataset dir (default: <data-dir>/dataset)")
    s.add_argument("--ratios", type=float, nargs=3, default=[0.8, 0.1, 0.1])
    s.add_argument("--seed", type=int, default=0)
    s.set_defaults(func=cmd_split)

    s = sub.add_parser("metrics", help="CK metrics and total LOC")
    s.add_argument("--ck-jar", type=Path, help="CK jar; omit to only re-sum existing results")
    s.set_defaults(func=cmd_metrics)

    s = sub.add_parser("c2v-paths", help="one path context per line from a .c2v file")
    s.add_argument("c2v_file", type=Path)
    s.add_argument("--out", type=Path)
    s.set_defaults(func=cmd_c2v)
    return p


def main(argv=None) -> int:
    a = parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if a.verbose else logging.INFO, format="%(levelname)s %(name)s: %(message)s"
    )
    if getattr(a, "out", None) is None and a.cmd in ("build", "split"):
        a.out = a.data_dir / "dataset"
    a.func(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
