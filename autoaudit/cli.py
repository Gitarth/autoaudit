"""
autoaudit command line.

    autoaudit crawl     search GitHub and download repos pinned to a commit (licenses logged)
    autoaudit extract   unzip downloads and list the Maven projects
    autoaudit joern     language-agnostic taint analysis with Joern -> SARIF
    autoaudit alerts    normalize SARIF from any analyzer into alerts.jsonl
    autoaudit context   show the source-to-sink code an analyst/LLM sees for one alert
    autoaudit prune     drop alerts whose every path runs through provably dead code (AST, no LLM)
    autoaudit triage    LLM verdict per alert (bring your own Anthropic / OpenAI-compatible key)
    autoaudit infer-spec  LLM-written taint rules tailored to one codebase
    autoaudit eval      score scanner and triage against OWASP Benchmark or hand labels
    autoaudit diagnose  rank calls typical of MISSED real vulns that no rule covers (rule gaps)
    autoaudit summarize-libs  LLM flow summaries for library calls on flows (Joern semantics)
    autoaudit sweep     dangerous calls no flow reaches, minus provably harmless ones -> alerts
    autoaudit opengrep  run Opengrep / Semgrep CE with autoaudit's own rules -> SARIF
    autoaudit variants  LLM generalises confirmed findings into new rules (rescan to find siblings)
    autoaudit alerts-diff  alerts in a new run that an old run did not report
    autoaudit confirm   (experimental) LLM-written harness tries to trigger an alert in a sandbox
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

from . import alerts, c2v, crawl, dataset, evaluate, joern, llm, metrics, projects, scan, specgen, triage
from .context import build_context
from .fpr import ANALYSIS_VALUES, FPR


def _read_alerts(paths: list[Path]) -> list:
    out, seen = [], set()
    for p in paths:
        for x in alerts.read_jsonl(p):
            if x.id not in seen:
                seen.add(x.id)
                out.append(x)
    return out


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
                a.max_flows,
                a.semantics,
            )
            counts[name] = n
            logging.info("%s: %d flows", name, n)
        except Exception as err:  # one bad project must not stop the batch
            logging.error("%s: %s", name, err)
            counts[name] = f"error: {err}".splitlines()[0]
    print(json.dumps(counts, indent=2))


def cmd_alerts(a):
    from . import ensemble

    paths = []
    for p in a.sarif:
        paths += sorted(p.glob("*.sarif")) if p.is_dir() else [p]
    found = []
    for p in paths:
        # <project>.sarif, <project>.opengrep.sarif, ... all belong to <project>
        found += alerts.read_sarif(p, project=p.name.split(".")[0])
    before = len(found)
    if not a.no_merge:
        found = ensemble.merge(found)
    attached = 0
    if a.src or a.attach_flows:
        from .codeindex import CodeIndex

        roots = {x.project: a.src or projects.source_root(a.data_dir / "repos" / x.project) for x in found}
        indexes = {proj: CodeIndex(root) for proj, root in roots.items() if root.exists()}
        attached = ensemble.attach_flows(found, joern.load_spec(a.spec), indexes)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    alerts.write_jsonl(found, a.out)
    by_rule = Counter(x.rule_id for x in found)
    by_tool = Counter(x.tool for x in found)
    agreed = sum(1 for x in found if x.also_reported_by)
    print(
        json.dumps(
            {
                "alerts": len(found),
                "before_merge": before,
                "files": len(paths),
                "by_tool": by_tool,
                "reported_by_several_tools": agreed,
                "flows_attached": attached,
                "by_rule": by_rule,
            },
            indent=2,
        )
    )


def cmd_opengrep(a):
    from . import ensemble

    roots = (
        [(a.name or a.src.resolve().name, a.src)] if a.src else projects.source_roots(a.data_dir / "repos")
    )
    for name, src in roots:
        out = a.data_dir / "sarif" / f"{name}.opengrep.sarif"
        ensemble.run_opengrep(src, out, a.config, a.binary, a.timeout)
        print(f"{name}: {out}")


def cmd_context(a):
    match = [x for x in _read_alerts(a.alerts) if x.id.startswith(a.alert_id)]
    if len(match) != 1:
        sys.exit(f"{len(match)} alerts match id {a.alert_id!r}")
    alert = match[0]
    root = a.src or projects.source_root(a.data_dir / "repos" / alert.project)
    print(f"{alert.rule_id} {', '.join(alert.cwes)} {alert.path}:{alert.line}\n{alert.message}\n")
    print(build_context(alert, root, window=a.window))


def _provider(a) -> llm.Provider:
    return llm.make_provider(
        a.provider, a.model, a.base_url, a.api_key_env, a.max_tokens_field, max_tokens=a.max_tokens
    )


def _add_llm_args(s):
    g = s.add_argument_group("LLM (bring your own key)")
    g.add_argument(
        "--provider",
        choices=["anthropic", "openai"],
        default="anthropic",
        help="'openai' means any OpenAI-compatible Chat Completions API",
    )
    g.add_argument("--model", help=f"default for anthropic: {llm.DEFAULT_MODELS['anthropic']}")
    g.add_argument("--base-url", help="API base URL (e.g. http://localhost:11434/v1 for Ollama)")
    g.add_argument(
        "--api-key-env", help="env var holding the key (default ANTHROPIC_API_KEY / OPENAI_API_KEY)"
    )
    g.add_argument("--max-tokens", type=int, default=2048)
    g.add_argument(
        "--max-tokens-field",
        default="max_tokens",
        help="openai only: use max_completion_tokens for newer OpenAI models",
    )
    g.add_argument("--price-in", type=float, help="USD per million input tokens (for cost reports)")
    g.add_argument("--price-out", type=float, help="USD per million output tokens")


def cmd_triage(a):
    found = _read_alerts(a.alerts)
    if a.rule:
        found = [x for x in found if x.rule_id in set(a.rule)]
    if a.limit:
        found = found[: a.limit]
    roots = {}
    for x in found:
        if x.project not in roots:
            roots[x.project] = a.src or projects.source_root(a.data_dir / "repos" / x.project)
    provider = _provider(a)
    stats = triage.triage(
        found,
        roots,
        provider,
        a.out,
        workers=a.workers,
        window=a.window,
        budget_usd=a.budget_usd,
        price_in=a.price_in,
        price_out=a.price_out,
        mode=a.mode,
        prune=a.prune,
        max_turns=a.max_turns,
    )
    print(json.dumps(stats, indent=2))


def cmd_prune(a):
    from . import codeindex, feasibility

    found = _read_alerts(a.alerts)
    indexes: dict[str, codeindex.CodeIndex] = {}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    pruned = 0
    with open(a.out, "a", encoding="utf-8") as fh:
        for x in found:
            if x.project not in indexes:
                indexes[x.project] = codeindex.CodeIndex(
                    a.src or projects.source_root(a.data_dir / "repos" / x.project)
                )
            dead = feasibility.infeasible(x, indexes[x.project])
            if dead is None:
                continue
            pruned += 1
            rec = triage._record(
                x, f"ast:{feasibility.VERSION}:{x.id}", "ast", feasibility.VERSION, feasibility.VERSION
            )
            rec.update(verdict="false_positive", confidence=1.0, reason=dead.reason)
            fh.write(json.dumps(rec) + "\n")
    print(json.dumps({"alerts": len(found), "pruned": pruned, "out": str(a.out)}, indent=2))


def cmd_infer_spec(a):
    base = joern.load_spec(a.base) if a.base else None
    evidence = json.loads(a.evidence.read_text()) if a.evidence else None
    spec, usage = specgen.infer_spec(a.src, _provider(a), base, evidence)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(spec, indent=2))
    print(
        json.dumps(
            {
                "rules": [r["id"] for r in spec["rules"]],
                "out": str(a.out),
                "usage": usage.__dict__,
                "cost_usd": usage.cost(a.price_in, a.price_out),
            },
            indent=2,
        )
    )


def cmd_eval(a):
    found = [x for x in _read_alerts(a.alerts) if 1 + len(x.also_reported_by) >= a.min_tools]
    results = evaluate.read_triage(a.triage) if a.triage else None
    report = {}
    if a.owasp:
        expected = evaluate.read_owasp_expected(a.owasp)
        report["scanner"] = evaluate.score_owasp(found, expected)
        if results is not None:
            report["scanner+triage"] = evaluate.score_owasp(found, expected, results, a.keep_uncertain)
            report["triage"] = evaluate.score_triage(evaluate.label_owasp_alerts(found, expected), results)
    if a.labels:
        if results is None:
            sys.exit("--labels needs --triage")
        report["triage_vs_labels"] = evaluate.score_triage(evaluate.read_labels(a.labels), results)
    if not report:
        sys.exit("give --owasp and/or --labels")
    print(json.dumps(report, indent=2))


def cmd_diagnose(a):
    from . import diagnose
    from .codeindex import CodeIndex

    found = _read_alerts(a.alerts)
    spec = joern.load_spec(a.spec)
    index = CodeIndex(a.src)
    if a.owasp:
        expected = evaluate.read_owasp_expected(a.owasp)
        truth = diagnose.owasp_truth(expected)
        by_name = {p.stem: p.relative_to(a.src).as_posix() for p in a.src.rglob("BenchmarkTest*.*")}
        report = diagnose.diagnose(found, truth, index, spec, file_of=by_name, top=a.top)
    elif a.truth:
        report = diagnose.diagnose(found, diagnose.read_truth(a.truth), index, spec, top=a.top)
    else:
        sys.exit("give --owasp or --truth")
    if a.json:
        print(json.dumps(report, indent=2))
    else:
        print(diagnose.format_report(report))


def cmd_summarize_libs(a):
    from . import libsum

    paths = []
    for p in a.externals:
        paths += sorted(p.glob("*.externals.tsv")) if p.is_dir() else [p]
    spec = joern.load_spec(a.spec)
    results, usage = libsum.summarize(libsum.read_externals(paths), spec, _provider(a), limit=a.limit)
    new_spec = libsum.write_outputs(results, spec, a.out)
    if a.spec_out:
        a.spec_out.write_text(json.dumps(new_spec, indent=2))
    counts = Counter(r["flow"] for r in results)
    print(
        json.dumps(
            {
                "classified": len(results),
                **counts,
                "semantics": str(a.out),
                "spec": str(a.spec_out) if a.spec_out else None,
                "usage": usage.__dict__,
                "cost_usd": usage.cost(a.price_in, a.price_out),
            },
            indent=2,
        )
    )


def cmd_sweep(a):
    from . import sweep
    from .codeindex import CodeIndex

    paths = []
    for p in a.sinks:
        paths += sorted(p.glob("*.sinks.jsonl")) if p.is_dir() else [p]
    sinks = sweep.read_sinks(paths)
    indexes = {}
    for proj in {s["project"] for s in sinks}:
        indexes[proj] = CodeIndex(a.src or projects.source_root(a.data_dir / "repos" / proj))
    found, stats = sweep.sweep(
        sinks, _read_alerts(a.alerts), joern.load_spec(a.spec), indexes, require_taint=a.require_taint
    )
    a.out.parent.mkdir(parents=True, exist_ok=True)
    alerts.write_jsonl(found, a.out)
    print(json.dumps({**stats, "out": str(a.out)}, indent=2))


def cmd_variants(a):
    from . import variants

    found = _read_alerts(a.alerts)
    records = evaluate.read_triage(a.triage) if a.triage else None
    labels = evaluate.read_labels(a.labels) if a.labels else None
    if records is None and labels is None:
        sys.exit("give --triage and/or --labels to say which alerts are confirmed")
    sure = variants.confirmed(found, records, labels)
    roots = {x.project: a.src or projects.source_root(a.data_dir / "repos" / x.project) for x in sure}
    spec, additions, usage = variants.propose(
        sure, roots, joern.load_spec(a.spec), _provider(a), limit=a.limit
    )
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(spec, indent=2))
    a.out.with_suffix(".additions.json").write_text(json.dumps(additions, indent=2))
    print(
        json.dumps(
            {
                "confirmed": len(sure),
                "rules_added_or_extended": len(additions["rules"]),
                "spec": str(a.out),
                "next": f"autoaudit joern --spec {a.out} ... then alerts-diff",
                "usage": usage.__dict__,
                "cost_usd": usage.cost(a.price_in, a.price_out),
            },
            indent=2,
        )
    )


def cmd_alerts_diff(a):
    from . import variants

    new = variants.diff(alerts.read_jsonl(a.old), alerts.read_jsonl(a.new))
    alerts.write_jsonl(new, a.out)
    print(
        json.dumps(
            {"new_alerts": len(new), "out": str(a.out), "by_rule": Counter(x.rule_id for x in new)}, indent=2
        )
    )


def cmd_confirm(a):
    from . import confirm

    found = _read_alerts(a.alerts)
    if a.ids:
        found = [x for x in found if any(x.id.startswith(i) for i in a.ids)]
    if a.triage:
        records = evaluate.read_triage(a.triage)
        found = [x for x in found if records.get(x.id, {}).get("verdict") in ("true_positive", "uncertain")]
    found = found[: a.limit]
    provider = _provider(a)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    counts: Counter = Counter()
    with open(a.out, "a", encoding="utf-8") as fh:
        for x in found:
            root = a.src or projects.source_root(a.data_dir / "repos" / x.project)
            res = confirm.confirm(
                x, root, provider, a.data_dir / "confirm" / x.id, a.sandbox, a.image, a.timeout
            )
            counts[res.status] += 1
            fh.write(json.dumps(res.__dict__) + "\n")
            logging.info("%s %s:%s -> %s", x.rule_id, x.path, x.line, res.status)
    print(json.dumps({"alerts": len(found), **counts, "out": str(a.out)}, indent=2))


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
    s.add_argument("--max-flows", type=int, default=200, help="cap on reported flows per rule per project")
    s.add_argument("--semantics", type=Path, help="library flow summaries (from summarize-libs)")
    s.set_defaults(func=cmd_joern)

    s = sub.add_parser("opengrep", help="run Opengrep / Semgrep CE with autoaudit's own rules")
    s.add_argument("--src", type=Path, help="scan this directory instead of <data-dir>/repos/*")
    s.add_argument("--name", help="project name for --src (default: directory name)")
    s.add_argument("--config", type=Path, help="rules file/dir (default: autoaudit/rules)")
    s.add_argument("--binary", help="opengrep or semgrep executable (default: whichever is installed)")
    s.add_argument("--timeout", type=int, default=None)
    s.set_defaults(func=cmd_opengrep)

    s = sub.add_parser("alerts", help="SARIF files (any analyzer) -> alerts.jsonl")
    s.add_argument("sarif", type=Path, nargs="+", help="SARIF files or directories")
    s.add_argument("--out", type=Path, default=None, help="default: <data-dir>/alerts.jsonl")
    s.add_argument("--no-merge", action="store_true", help="keep duplicate alerts from different tools")
    s.add_argument("--src", type=Path, help="source root, to attach approximate flows to flow-less alerts")
    s.add_argument(
        "--attach-flows",
        action="store_true",
        help="attach flows using <data-dir>/repos/<project> as source roots",
    )
    s.add_argument("--spec", type=Path, default=joern.DEFAULT_SPEC, help="rules used to attach flows")
    s.set_defaults(func=cmd_alerts)

    s = sub.add_parser("context", help="print the flow context for one alert")
    s.add_argument("alert_id", help="alert id (a unique prefix is enough)")
    s.add_argument(
        "--alerts",
        type=Path,
        nargs="+",
        default=None,
        help="alert files (default: <data-dir>/alerts.jsonl); e.g. add sweep.jsonl",
    )
    s.add_argument("--src", type=Path, help="source root (default: <data-dir>/repos/<project>)")
    s.add_argument("--window", type=int, default=6, help="lines of context around each step")
    s.set_defaults(func=cmd_context)

    s = sub.add_parser("triage", help="LLM verdict for each alert; appends to <data-dir>/triage.jsonl")
    s.add_argument(
        "--alerts",
        type=Path,
        nargs="+",
        default=None,
        help="alert files (default: <data-dir>/alerts.jsonl); e.g. add sweep.jsonl",
    )
    s.add_argument("--out", type=Path, default=None, help="default: <data-dir>/triage.jsonl")
    s.add_argument(
        "--src", type=Path, help="source root for all alerts (default: <data-dir>/repos/<project>)"
    )
    s.add_argument("--rule", nargs="*", help="only these rule ids")
    s.add_argument("--limit", type=int, help="triage at most N alerts (try it on a sample first)")
    s.add_argument("--workers", type=int, default=4)
    s.add_argument("--window", type=int, default=8, help="lines of context around each flow step")
    s.add_argument("--budget-usd", type=float, help="stop starting new requests past this spend")
    s.add_argument(
        "--mode",
        choices=["snippet", "agent"],
        default="snippet",
        help="agent: the model investigates with AST navigation tools (more tokens, more context)",
    )
    s.add_argument("--max-turns", type=int, default=8, help="agent mode: tool-use turns per alert")
    s.add_argument(
        "--no-prune",
        dest="prune",
        action="store_false",
        help="also send alerts on provably dead paths to the LLM",
    )
    _add_llm_args(s)
    s.set_defaults(func=cmd_triage)

    s = sub.add_parser("prune", help="AST feasibility check; writes false_positive verdicts (no LLM)")
    s.add_argument(
        "--alerts",
        type=Path,
        nargs="+",
        default=None,
        help="alert files (default: <data-dir>/alerts.jsonl); e.g. add sweep.jsonl",
    )
    s.add_argument("--out", type=Path, default=None, help="default: <data-dir>/triage.jsonl")
    s.add_argument(
        "--src", type=Path, help="source root for all alerts (default: <data-dir>/repos/<project>)"
    )
    s.set_defaults(func=cmd_prune)

    s = sub.add_parser("infer-spec", help="LLM-written taint spec for one codebase")
    s.add_argument("--src", type=Path, required=True, help="repository root")
    s.add_argument("--out", type=Path, required=True, help="where to write the spec JSON")
    s.add_argument("--base", type=Path, help="baseline spec to extend; the result is merged into it")
    s.add_argument(
        "--evidence", type=Path, help="`autoaudit diagnose --json` report of missed vulnerabilities"
    )
    _add_llm_args(s)
    s.set_defaults(func=cmd_infer_spec)

    s = sub.add_parser("eval", help="score scanner and triage against ground truth")
    s.add_argument(
        "--alerts",
        type=Path,
        nargs="+",
        default=None,
        help="alert files (default: <data-dir>/alerts.jsonl); e.g. add sweep.jsonl",
    )
    s.add_argument("--triage", type=Path, help="triage results (JSONL)")
    s.add_argument("--owasp", type=Path, help="OWASP Benchmark expectedresults-*.csv")
    s.add_argument("--labels", type=Path, help="hand labels CSV: alert_id,label")
    s.add_argument(
        "--min-tools",
        type=int,
        default=1,
        help="only count alerts reported by at least this many tools (corroboration)",
    )
    s.add_argument(
        "--drop-uncertain",
        dest="keep_uncertain",
        action="store_false",
        help="treat 'uncertain' verdicts as dismissed (default: kept)",
    )
    s.set_defaults(func=cmd_eval)

    s = sub.add_parser("diagnose", help="find rule gaps from missed real vulnerabilities")
    s.add_argument("--src", type=Path, required=True, help="source root the alerts refer to")
    s.add_argument(
        "--alerts",
        type=Path,
        nargs="+",
        default=None,
        help="alert files (default: <data-dir>/alerts.jsonl); e.g. add sweep.jsonl",
    )
    s.add_argument("--spec", type=Path, default=joern.DEFAULT_SPEC, help="the spec that produced the alerts")
    s.add_argument("--owasp", type=Path, help="OWASP Benchmark expectedresults-*.csv")
    s.add_argument("--truth", type=Path, help="CSV with columns path,cwe,real")
    s.add_argument("--top", type=int, default=15)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_diagnose)

    s = sub.add_parser("summarize-libs", help="LLM flow summaries for library methods on reported flows")
    s.add_argument("externals", type=Path, nargs="+", help="*.externals.tsv files or dirs (written by joern)")
    s.add_argument("--spec", type=Path, default=joern.DEFAULT_SPEC)
    s.add_argument(
        "--out", type=Path, required=True, help="semantics file to write (pass to joern --semantics)"
    )
    s.add_argument("--spec-out", type=Path, help="write the spec with LLM-identified sanitizers added")
    s.add_argument("--limit", type=int, default=120, help="most frequent methods to classify")
    _add_llm_args(s)
    s.set_defaults(func=cmd_summarize_libs)

    s = sub.add_parser("sweep", help="flow-less alerts for dangerous calls that no flow reaches")
    s.add_argument("sinks", type=Path, nargs="+", help="*.sinks.jsonl files or dirs (written by joern)")
    s.add_argument(
        "--alerts",
        type=Path,
        nargs="+",
        default=None,
        help="existing alerts (default: <data-dir>/alerts.jsonl)",
    )
    s.add_argument("--spec", type=Path, default=joern.DEFAULT_SPEC)
    s.add_argument("--src", type=Path, help="source root (default: <data-dir>/repos/<project>)")
    s.add_argument("--out", type=Path, default=None, help="default: <data-dir>/sweep.jsonl")
    s.add_argument(
        "--all-nonconstant",
        dest="require_taint",
        action="store_false",
        help="keep sinks even when no argument syntactically derives from user input",
    )
    s.set_defaults(func=cmd_sweep)

    s = sub.add_parser("variants", help="generalise confirmed findings into new rules")
    s.add_argument("--alerts", type=Path, nargs="+", default=None, help="default: <data-dir>/alerts.jsonl")
    s.add_argument("--triage", type=Path, help="triage results; true_positive verdicts count as confirmed")
    s.add_argument("--labels", type=Path, help="CSV alert_id,label of confirmed findings")
    s.add_argument("--spec", type=Path, default=joern.DEFAULT_SPEC, help="spec to extend")
    s.add_argument("--src", type=Path, help="source root (default: <data-dir>/repos/<project>)")
    s.add_argument("--out", type=Path, required=True, help="extended spec to write")
    s.add_argument("--limit", type=int, default=12, help="confirmed findings to show the model")
    _add_llm_args(s)
    s.set_defaults(func=cmd_variants)

    s = sub.add_parser("alerts-diff", help="alerts in NEW that OLD did not report (e.g. variants)")
    s.add_argument("old", type=Path)
    s.add_argument("new", type=Path)
    s.add_argument("--out", type=Path, required=True)
    s.set_defaults(func=cmd_alerts_diff)

    s = sub.add_parser("confirm", help="(experimental) try to trigger alerts in a sandbox")
    s.add_argument("--alerts", type=Path, nargs="+", default=None, help="default: <data-dir>/alerts.jsonl")
    s.add_argument("--ids", nargs="*", help="alert ids (prefixes) to confirm")
    s.add_argument("--triage", type=Path, help="only alerts triaged true_positive or uncertain")
    s.add_argument("--src", type=Path, help="source root (default: <data-dir>/repos/<project>)")
    s.add_argument("--limit", type=int, default=10)
    s.add_argument(
        "--sandbox",
        choices=["auto", "container", "local"],
        default="auto",
        help="'local' runs generated code on this machine: only for code you trust",
    )
    s.add_argument("--image", help="container image (default per language)")
    s.add_argument("--timeout", type=int, default=120, help="seconds per harness run")
    s.add_argument("--out", type=Path, default=None, help="default: <data-dir>/confirm.jsonl")
    _add_llm_args(s)
    s.set_defaults(func=cmd_confirm)

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
    if (
        a.cmd in ("context", "triage", "eval", "prune", "diagnose", "sweep", "variants", "confirm")
        and a.alerts is None
    ):
        a.alerts = [a.data_dir / "alerts.jsonl"]
    if a.cmd == "confirm" and a.out is None:
        a.out = a.data_dir / "confirm.jsonl"
    if a.cmd == "sweep" and a.out is None:
        a.out = a.data_dir / "sweep.jsonl"
    if a.cmd in ("triage", "prune") and a.out is None:
        a.out = a.data_dir / "triage.jsonl"
    a.func(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
