"""
autoaudit command line.

    autoaudit crawl     search GitHub and download repos pinned to a commit (licenses logged)
    autoaudit extract   unzip downloads and list the Maven projects
    autoaudit joern     language-agnostic taint analysis with Joern -> SARIF
    autoaudit alerts    normalize SARIF from any analyzer into alerts.jsonl
    autoaudit context   show the source-to-sink code an analyst/LLM sees for one alert
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
from collections import Counter
from pathlib import Path

from . import alerts, c2v, crawl, dataset, joern, metrics, projects, scan
from .context import build_context
from .fpr import ANALYSIS_VALUES, FPR


def _projects(data: Path) -> list[tuple[str, Path]]:
    return [(p.relative_to(data / "repos").parts[0], p) for p in projects.maven_projects(data / "repos")]


def cmd_crawl(a):
    allow = set(a.allow_license) if a.allow_license else None
    rows = crawl.crawl(a.data_dir, a.query, a.limit, a.min_size_kb, allow_licenses=allow)
    licenses = Counter(r.get("license") or crawl.NO_LICENSE for r in rows)
    print(f"{len(rows)} repositories in {a.data_dir / 'repos.csv'}")
    print(json.dumps({"licenses": dict(licenses.most_common())}, indent=2))


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


def _roots(a) -> list[tuple[str, Path]]:
    if getattr(a, "src", None):
        return [(a.name or a.src.resolve().name, a.src)]
    roots = projects.source_roots(a.data_dir / "repos")
    if getattr(a, "only", None):
        roots = [r for r in roots if r[0] in set(a.only)]
    return roots


def cmd_joern(a):
    spec = joern.load_spec(a.spec)
    counts = {}
    for name, src in _roots(a):
        try:
            n = joern.scan(
                src,
                spec,
                a.data_dir / "sarif" / f"{name}.sarif",
                a.data_dir / "cpg",
                a.bin_dir,
                a.language,
                a.timeout,
            )
            counts[name] = n
            logging.info("%s: %d flows", name, n)
        except Exception as err:  # one bad project must not stop the batch
            logging.error("%s: %s", name, err)
            counts[name] = f"error: {err}".splitlines()[0]
    print(json.dumps(counts, indent=2))


def cmd_alerts(a):
    paths = []
    for p in a.sarif:
        paths += sorted(p.glob("*.sarif")) if p.is_dir() else [p]
    found = []
    for p in paths:
        found += alerts.read_sarif(p, project=p.stem)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    alerts.write_jsonl(found, a.out)
    by_rule: dict[str, int] = {}
    for x in found:
        by_rule[x.rule_id] = by_rule.get(x.rule_id, 0) + 1
    print(json.dumps({"alerts": len(found), "files": len(paths), "by_rule": by_rule}, indent=2))


def cmd_context(a):
    match = [x for x in alerts.read_jsonl(a.alerts) if x.id.startswith(a.alert_id)]
    if len(match) != 1:
        sys.exit(f"{len(match)} alerts match id {a.alert_id!r}")
    alert = match[0]
    root = a.src or projects.source_root(a.data_dir / "repos" / alert.project)
    print(f"{alert.rule_id} {', '.join(alert.cwes)} {alert.path}:{alert.line}\n{alert.message}\n")
    print(build_context(alert, root, window=a.window))


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
    s.add_argument(
        "--allow-license",
        nargs="+",
        metavar="SPDX",
        help="only download repos under these licenses (default: all, but every license is logged)",
    )
    s.set_defaults(func=cmd_crawl)

    s = sub.add_parser("extract", help="unzip downloads and find Maven projects")
    s.set_defaults(func=cmd_extract)

    s = sub.add_parser("joern", help="taint analysis with Joern; writes <data-dir>/sarif/<project>.sarif")
    s.add_argument("--spec", type=Path, default=joern.DEFAULT_SPEC, help="taint rule spec (JSON)")
    s.add_argument("--src", type=Path, help="scan this directory instead of <data-dir>/repos/*")
    s.add_argument("--name", help="project name for --src (default: directory name)")
    s.add_argument("--only", nargs="*", help="scan only these projects under <data-dir>/repos")
    s.add_argument("--bin-dir", type=Path, help="directory with joern and joern-parse (env: JOERN_HOME)")
    s.add_argument("--language", help="force a Joern frontend, e.g. java, pythonsrc, jssrc")
    s.add_argument("--timeout", type=int, default=None, help="seconds per Joern step")
    s.set_defaults(func=cmd_joern)

    s = sub.add_parser("alerts", help="SARIF files (any analyzer) -> alerts.jsonl")
    s.add_argument("sarif", type=Path, nargs="+", help="SARIF files or directories")
    s.add_argument("--out", type=Path, default=None, help="default: <data-dir>/alerts.jsonl")
    s.set_defaults(func=cmd_alerts)

    s = sub.add_parser("context", help="print the flow context for one alert")
    s.add_argument("alert_id", help="alert id (a unique prefix is enough)")
    s.add_argument("--alerts", type=Path, default=None, help="default: <data-dir>/alerts.jsonl")
    s.add_argument("--src", type=Path, help="source root (default: <data-dir>/repos/<project>)")
    s.add_argument("--window", type=int, default=6, help="lines of context around each step")
    s.set_defaults(func=cmd_context)

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
    if a.cmd == "alerts" and a.out is None:
        a.out = a.data_dir / "alerts.jsonl"
    if a.cmd == "context" and a.alerts is None:
        a.alerts = a.data_dir / "alerts.jsonl"
    a.func(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
