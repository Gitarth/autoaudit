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
    autoaudit fpr-import  audited Fortify FPRs -> alerts + sources + labels for learned triage
    autoaudit ml-dataset  alerts -> features + code graphs + labels for learned triage (JSONL)
    autoaudit ml-train  cross-validate and train GBDT / Devign-style GGNN triage models
    autoaudit ml-predict  score alerts with a trained model -> triage verdicts
    autoaudit bench     known-vulnerable commits of real projects: fetch, scan, score detection
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
import shutil
import sys
from collections import Counter
from pathlib import Path

from . import (
    alerts,
    bench,
    c2v,
    crawl,
    dataset,
    evaluate,
    joern,
    llm,
    metrics,
    projects,
    scan,
    specgen,
    triage,
)
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
    found = _read_alerts(a.alerts)
    pruned = _prune(found, lambda p: a.src or projects.source_root(a.data_dir / "repos" / p), a.out)
    print(json.dumps({"alerts": len(found), "pruned": pruned, "out": str(a.out)}, indent=2))


def _prune(found: list, root_of, out: Path) -> int:
    """Append a false_positive verdict to `out` for every provably infeasible alert."""
    from . import codeindex, feasibility

    indexes: dict[str, codeindex.CodeIndex] = {}
    out.parent.mkdir(parents=True, exist_ok=True)
    pruned = 0
    with open(out, "a", encoding="utf-8") as fh:
        for x in found:
            if x.project not in indexes:
                indexes[x.project] = codeindex.CodeIndex(root_of(x.project))
            dead = feasibility.infeasible(x, indexes[x.project])
            if dead is None:
                continue
            pruned += 1
            rec = triage._record(
                x, f"ast:{feasibility.VERSION}:{x.id}", "ast", feasibility.VERSION, feasibility.VERSION
            )
            rec.update(verdict="false_positive", confidence=1.0, reason=dead.reason)
            fh.write(json.dumps(rec) + "\n")
    return pruned


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


def _root_of(a):
    if a.src:
        return lambda p: a.src
    if getattr(a, "src_dir", None):
        return lambda p: a.src_dir / p
    return lambda p: projects.source_root(a.data_dir / "repos" / p)


def cmd_fpr_import(a):
    from . import fortify

    summary = fortify.import_fprs(
        dataset.find_fprs(a.fprs),
        a.src_dir or a.data_dir / "fortify-src",
        a.out or a.data_dir / "fortify_alerts.jsonl",
        a.labels_out or a.data_dir / "fortify_labels.csv",
        a.positive,
        a.negative,
    )
    print(json.dumps(summary, indent=2))


def cmd_ml_dataset(a):
    from .ml import data

    found = _read_alerts(a.alerts)
    labels: dict[str, tuple[bool, str]] = {}
    if a.triage:
        # never learn from deterministic pruning or from a model's own predictions
        recs = {
            k: r
            for k, r in evaluate.read_triage(a.triage).items()
            if r.get("provider") not in ("ast", "model")
        }
        labels.update({k: (v, "triage") for k, v in data.labels_from_triage(recs).items()})
    if a.owasp:
        expected = evaluate.read_owasp_expected(a.owasp)
        labels.update({k: (v, "owasp") for k, v in evaluate.label_owasp_alerts(found, expected).items()})
    if a.labels:
        with open(a.labels, newline="", encoding="utf-8") as fh:
            sources = {r["alert_id"]: r.get("source") or "hand" for r in csv.DictReader(fh)}
        labels.update({k: (v, sources.get(k, "hand")) for k, v in evaluate.read_labels(a.labels).items()})
    recs = data.build(
        found, _root_of(a), labels, graph=not a.no_graph, group=a.group, only_labeled=a.only_labeled
    )
    data.write(recs, a.out)
    lab = [r["label"] for r in recs if r["label"] is not None]
    print(
        json.dumps(
            {
                "examples": len(recs),
                "labeled": len(lab),
                "real": sum(lab),
                "groups": len({r["group"] for r in recs}),
                "with_graph": sum(1 for r in recs if r.get("graph")),
                "out": str(a.out),
            },
            indent=2,
        )
    )


def _model_kwargs(a) -> dict:
    return {"epochs": a.epochs, "hidden": a.hidden, "steps": a.steps}


def cmd_ml_train(a):
    from .ml import data, models

    recs = [r for r in data.read(a.dataset) if r["label"] is not None]
    if a.label_sources:
        recs = [r for r in recs if r.get("label_source") in set(a.label_sources)]
    if a.model != "gbdt":
        recs = [r for r in recs if r.get("graph")]
    if len({r["label"] for r in recs}) < 2:
        sys.exit("need labeled examples of both classes")
    y = [int(r["label"]) for r in recs]
    report: dict = {
        "model": a.model,
        "examples": len(recs),
        "real": sum(y),
        "groups": len({r["group"] for r in recs}),
    }
    threshold, oof_grouped = None, None
    for split in a.cv:
        oof = models.cross_validate(recs, a.model, split, a.folds, a.seed, **_model_kwargs(a))
        t = models.threshold_for_recall(oof, y, a.target_recall)
        report[f"cv_{split}"] = models.metrics(oof, y, t)
        if split == "grouped" or threshold is None:
            threshold, oof_grouped = t, oof
    if threshold is None:
        threshold = 0.5
    if a.oof_out and oof_grouped is not None:
        _write_model_triage(recs, oof_grouped, threshold, f"{a.model}-oof", a.oof_out)
        report["oof_out"] = str(a.oof_out)
    if a.out:
        model = models.make(a.model, seed=a.seed, **_model_kwargs(a)).fit(recs, y)
        meta = {
            "threshold": threshold,
            "target_recall": a.target_recall,
            "trained_on": str(a.dataset),
            "examples": len(recs),
            "cv": {k: v for k, v in report.items() if k.startswith("cv_")},
        }
        models.save(model, a.out, meta)
        report["out"] = str(a.out)
    report["threshold"] = round(threshold, 4)
    print(json.dumps(report, indent=2))


def _write_model_triage(recs: list[dict], probs: list[float], threshold: float, name: str, out: Path) -> int:
    from .ml.models import MODEL_VERSION

    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "a", encoding="utf-8") as fh:
        for r, p in zip(recs, probs):
            real = p >= threshold
            fh.write(
                json.dumps(
                    {
                        "key": f"model:{name}:{r['alert_id']}",
                        "alert_id": r["alert_id"],
                        "project": r["project"],
                        "rule_id": r["rule_id"],
                        "cwes": r["cwes"],
                        "path": r["path"],
                        "line": r["line"],
                        "provider": "model",
                        "model": name,
                        "prompt_version": MODEL_VERSION,
                        "verdict": "true_positive" if real else "false_positive",
                        "confidence": round(p if real else 1 - p, 4),
                        "reason": f"learned triage {name}: P(real) = {p:.3f}, threshold {threshold:.3f}",
                    }
                )
                + "\n"
            )
    return len(recs)


def cmd_ml_predict(a):
    from .ml import data, models

    model, meta = models.load(a.model)
    found = _read_alerts(a.alerts)
    done = evaluate.read_triage(a.out) if a.out.exists() and not a.overwrite else {}
    found = [x for x in found if x.id not in done]
    recs = data.build(found, _root_of(a), {}, graph=meta["kind"] != "gbdt")
    if meta["kind"] != "gbdt":
        recs = [r for r in recs if r.get("graph")]
    threshold = a.threshold if a.threshold is not None else meta["threshold"]
    probs = model.predict(recs) if recs else []
    _write_model_triage(recs, probs, threshold, a.model.name, a.out)
    dismissed = sum(p < threshold for p in probs)
    print(
        json.dumps(
            {"scored": len(recs), "already_triaged": len(done), "dismissed": dismissed, "out": str(a.out)},
            indent=2,
        )
    )


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


def cmd_bench(a):
    root = a.data_dir / "bench"
    cases = bench.load_corpus(a.corpus)
    if a.only:
        cases = [c for c in cases if c.name in set(a.only)]
    fixed = a.fixed or a.stage == "label"
    if a.stage in ("fetch", "all", "label") and (a.stage != "label" or not (root / "truth.json").exists()):
        truth = bench.fetch(cases, root, a.timeout)
        ok = sum(1 for t in truth.values() if "error" not in t)
        print(f"{ok}/{len(truth)} cases checked out under {root / 'repos'}; truth in {root / 'truth.json'}")
    truth_path = root / "truth.json"
    if not truth_path.exists():
        sys.exit(f"no {truth_path}: run `autoaudit bench fetch` first")
    names = {c.name for c in cases}
    truth = {n: t for n, t in json.loads(truth_path.read_text()).items() if n in names}
    ok_names = [n for n, t in truth.items() if "error" not in t]
    languages = {c.name: c.language for c in cases}
    if fixed and a.stage in ("fetch", "all", "label"):
        by_name = {c.name: c for c in cases}
        for n in ok_names:
            try:
                bench.checkout_fixed(by_name[n], root / "repos" / n, root / "fixed" / n, a.timeout)
            except Exception as err:  # one repository must not stop the rest
                logging.error("%s: fixed checkout failed: %s", n, str(err).splitlines()[0])
    if a.stage in ("scan", "all") or (a.stage == "label" and not (root / "alerts.jsonl").exists()):
        # alerts are collected for every checked-out case, so --only rescans a few
        # cases (or one scanner) without dropping the others' alerts
        everything = [n for n, t in json.loads(truth_path.read_text()).items() if "error" not in t]
        _bench_scan(a, root, ok_names, languages, collect=everything)
        if fixed:
            done = [n for n in everything if (root / "fixed" / n).exists()]
            _bench_scan(a, root, [n for n in done if n in ok_names], languages, "fixed", collect=done)
    if a.stage in ("score", "all"):
        found = _read_alerts(a.alerts or [root / "alerts.jsonl"])
        triage_path = a.triage or root / "triage.jsonl"
        results = evaluate.read_triage(triage_path) if triage_path.exists() else None
        report = bench.score(truth, found, results, a.keep_uncertain, a.tolerance, a.any_cwe)
        (root / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        table = bench.markdown(report)
        (root / "report.md").write_text(table, encoding="utf-8")
        print(table + f"\nDetails: {root / 'report.json'}")
    if a.stage == "label" or (fixed and a.stage == "all"):
        _bench_label(a, root, truth)


def _bench_tools(sarif: Path) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for p in sarif.glob("*.sarif") if sarif.exists() else []:
        name, *rest = p.name.split(".")
        out.setdefault(name, set()).add(rest[0] if len(rest) > 1 else "joern")
    return out


def _bench_label(a, root: Path, truth: dict) -> None:
    vuln = _read_alerts([root / "alerts.jsonl"])
    fixed_path = root / "alerts-fixed.jsonl"
    if not fixed_path.exists():
        sys.exit(f"no {fixed_path}: run `autoaudit bench scan --fixed` first")
    fixed = _read_alerts([fixed_path])
    tools_v, tools_f = _bench_tools(root / "sarif"), _bench_tools(root / "sarif-fixed")
    # a case is labeled only if the same scanners ran on both versions: an alert
    # that "disappears" because a scanner failed on the fix is not a real finding
    scanned = {n for n in truth if tools_v.get(n) and tools_v.get(n) == tools_f.get(n)}
    labels, stats = bench.label(
        truth, vuln, fixed, root / "repos", root / "fixed", scanned, a.tolerance, a.weak_negatives
    )
    with open(root / "labels.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["alert_id", "label", "source"])
        for aid, (lab, src) in labels.items():
            w.writerow([aid, "true" if lab else "false", src])
    summary = {
        "labeled": len(labels),
        "real": sum(1 for v, _ in labels.values() if v),
        "false": sum(1 for v, _ in labels.values() if not v),
        "cases_labeled": len(stats),
        "cases_without_real": sorted(n for n, st in stats.items() if not st["real"]),
        "cases_skipped": sorted(set(truth) - scanned),
        "per_case": stats,
        "out": str(root / "labels.csv"),
    }
    (root / "labels-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "per_case"}, indent=2))


def _bench_scan(
    a,
    root: Path,
    names: list[str],
    languages: dict | None = None,
    version: str = "vulnerable",
    collect: list[str] | None = None,
) -> None:
    """Scan `names`, then rebuild the alert file from the SARIF of every case in
    `collect` (default: `names`)."""
    from . import codeindex, ensemble

    src_root, sarif, out = (
        (root / "repos", root / "sarif", root / "alerts.jsonl")
        if version == "vulnerable"
        else (root / "fixed", root / "sarif-fixed", root / "alerts-fixed.jsonl")
    )
    languages = languages or {}
    opengrep = shutil.which("opengrep") or shutil.which("semgrep")
    scanners = a.scanners or [
        s for s, ok in (("joern", joern.available(a.bin_dir)), ("opengrep", bool(opengrep))) if ok
    ]
    if not scanners:
        sys.exit("no scanner found: install Joern and/or Opengrep (or Semgrep CE), or pass --scanners")
    spec = joern.load_spec(a.spec)
    for name in names:
        src = src_root / name
        for tool in scanners:
            if tool == "joern" and languages.get(name) not in (None, "java"):
                continue  # the bundled Joern spec is Java's; Opengrep covers the other languages
            target = sarif / (f"{name}.sarif" if tool == "joern" else f"{name}.opengrep.sarif")
            if getattr(a, "reuse", False) and target.exists():
                continue
            try:
                if tool == "joern":
                    out_sarif = sarif / f"{name}.sarif"
                    joern.scan(src, spec, out_sarif, root / "cpg", a.bin_dir, None, a.timeout, a.max_flows)
                else:
                    out_sarif = sarif / f"{name}.opengrep.sarif"
                    ensemble.run_opengrep(src, out_sarif, None, None, a.timeout)
                logging.info("%s (%s): %s done", name, version, tool)
            except Exception as err:  # one project or tool failing must not stop the batch
                logging.error(
                    "%s (%s): %s failed: %s",
                    name,
                    version,
                    tool,
                    str(err).splitlines()[0] if str(err) else err,
                )

    collect = set(collect or names)
    found = []
    for p in sorted(sarif.glob("*.sarif")) if sarif.exists() else []:
        project = p.name.split(".")[0]
        if project in collect:
            found += alerts.read_sarif(p, project=project)
    found = ensemble.merge(found)
    if codeindex.available():  # flows for flow-less alerts, so `flow` matching and prune work on them
        indexes = {n: codeindex.CodeIndex(src_root / n) for n in sorted(collect)}
        ensemble.attach_flows(found, spec, indexes)
    alerts.write_jsonl(found, out)
    pruned = 0
    if version == "vulnerable" and a.prune and codeindex.available():
        (root / "triage.jsonl").unlink(missing_ok=True)  # prune verdicts for exactly these alerts
        pruned = _prune(found, lambda p: src_root / p, root / "triage.jsonl")
    print(f"{len(found)} alerts ({', '.join(scanners)}, {version}) -> {out}; {pruned} pruned")


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

    s = sub.add_parser("fpr-import", help="audited Fortify FPRs -> alerts, sources and labels for ml-dataset")
    s.add_argument("fprs", type=Path, help="an .fpr file or a directory of them")
    s.add_argument(
        "--src-dir", type=Path, help="sources go to <src-dir>/<project> (default: <data-dir>/fortify-src)"
    )
    s.add_argument("--out", type=Path, help="alerts (default: <data-dir>/fortify_alerts.jsonl)")
    s.add_argument("--labels-out", type=Path, help="labels CSV (default: <data-dir>/fortify_labels.csv)")
    s.add_argument(
        "--positive", nargs="+", default=["Suspicious", "Exploitable"], help="verdicts labeled real"
    )
    s.add_argument("--negative", nargs="+", default=["Not an Issue"], help="verdicts labeled false")
    s.set_defaults(func=cmd_fpr_import)

    s = sub.add_parser("ml-dataset", help="features + code graphs + labels per alert (learned triage)")
    s.add_argument("--alerts", type=Path, nargs="+", default=None, help="default: <data-dir>/alerts.jsonl")
    s.add_argument(
        "--src", type=Path, help="source root for all alerts (default: <data-dir>/repos/<project>)"
    )
    s.add_argument("--src-dir", type=Path, help="one source tree per project: <src-dir>/<project>")
    s.add_argument("--owasp", type=Path, help="labels from OWASP Benchmark expectedresults-*.csv")
    s.add_argument("--labels", type=Path, help="hand labels CSV: alert_id,label (wins over other sources)")
    s.add_argument("--triage", type=Path, help="labels from earlier LLM triage verdicts (uncertain ignored)")
    s.add_argument(
        "--group",
        choices=["slice", "file", "project", "cwe"],
        default="slice",
        help="grouping for leakage-safe CV: abstracted slice (default), file, project or CWE",
    )
    s.add_argument("--only-labeled", action="store_true")
    s.add_argument("--no-graph", action="store_true", help="features only (enough for gbdt)")
    s.add_argument("--out", type=Path, required=True, help="dataset JSONL (.gz to compress)")
    s.set_defaults(func=cmd_ml_dataset)

    s = sub.add_parser("ml-train", help="cross-validate and train a triage model (needs [ml] extra)")
    s.add_argument("--dataset", type=Path, required=True)
    s.add_argument("--model", choices=["gbdt", "ggnn", "hybrid"], default="gbdt")
    s.add_argument(
        "--cv",
        nargs="*",
        choices=["random", "grouped", "cwe"],
        default=["random", "grouped"],
        help="cross-validation schemes to report (the threshold comes from 'grouped')",
    )
    s.add_argument("--folds", type=int, default=5)
    s.add_argument(
        "--label-sources",
        nargs="+",
        help="train only on these label sources (e.g. hand owasp fix persists triage)",
    )
    s.add_argument(
        "--target-recall",
        type=float,
        default=0.98,
        help="share of real findings the decision threshold must keep (default 0.98)",
    )
    s.add_argument("--oof-out", type=Path, help="write out-of-fold verdicts (triage JSONL) for `eval`")
    s.add_argument("--out", type=Path, help="model directory; omit to only cross-validate")
    s.add_argument("--seed", type=int, default=0)
    s.add_argument("--epochs", type=int, default=30, help="GGNN: max epochs (early stopping)")
    s.add_argument("--hidden", type=int, default=64, help="GGNN: hidden size")
    s.add_argument("--steps", type=int, default=4, help="GGNN: message-passing steps")
    s.set_defaults(func=cmd_ml_train)

    s = sub.add_parser("ml-predict", help="score alerts with a trained model -> triage verdicts")
    s.add_argument("--model", type=Path, required=True, help="model directory from ml-train --out")
    s.add_argument("--alerts", type=Path, nargs="+", default=None, help="default: <data-dir>/alerts.jsonl")
    s.add_argument(
        "--src", type=Path, help="source root for all alerts (default: <data-dir>/repos/<project>)"
    )
    s.add_argument("--src-dir", type=Path, help="one source tree per project: <src-dir>/<project>")
    s.add_argument("--threshold", type=float, help="override the model's threshold")
    s.add_argument(
        "--overwrite",
        action="store_true",
        help="also score alerts that already have a verdict in --out (default: keep prune/LLM verdicts)",
    )
    s.add_argument("--out", type=Path, default=None, help="default: <data-dir>/triage.jsonl")
    s.set_defaults(func=cmd_ml_predict)

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

    s = sub.add_parser(
        "bench", help="fetch known-vulnerable commits of real projects, scan them, score detection"
    )
    s.add_argument(
        "stage",
        nargs="?",
        default="all",
        choices=["fetch", "scan", "score", "label", "all"],
        help="fetch: checkout + ground truth; scan: analyzers -> alerts, prune; score: report; "
        "label: training labels from scanning before and after each fix (default: all)",
    )
    s.add_argument(
        "--fixed",
        action="store_true",
        help="also check out and scan each fix commit (needed by `label`; implied by it)",
    )
    s.add_argument("--reuse", action="store_true", help="scan: keep SARIF already written for a case")
    s.add_argument(
        "--no-weak-negatives",
        dest="weak_negatives",
        action="store_false",
        help="label: only label real findings, not alerts that survive the fix",
    )
    s.add_argument("--corpus", type=Path, default=bench.DEFAULT_CORPUS, help="cases JSON")
    s.add_argument("--only", nargs="*", help="only these case names")
    s.add_argument(
        "--scanners", nargs="+", choices=["joern", "opengrep"], help="default: every installed one"
    )
    s.add_argument("--spec", type=Path, default=joern.DEFAULT_SPEC, help="taint rule spec (JSON)")
    s.add_argument("--bin-dir", type=Path, help="directory with joern and joern-parse (env: JOERN_HOME)")
    s.add_argument("--max-flows", type=int, default=200, help="cap on reported flows per rule per project")
    s.add_argument("--timeout", type=int, default=None, help="seconds per git fetch / scanner step")
    s.add_argument("--no-prune", dest="prune", action="store_false", help="skip the AST feasibility check")
    s.add_argument(
        "--alerts", type=Path, nargs="+", help="score these (default: <data-dir>/bench/alerts.jsonl)"
    )
    s.add_argument("--triage", type=Path, help="verdicts (default: <data-dir>/bench/triage.jsonl if present)")
    s.add_argument(
        "--drop-uncertain",
        dest="keep_uncertain",
        action="store_false",
        help="treat 'uncertain' verdicts as dismissed (default: kept)",
    )
    s.add_argument("--tolerance", type=int, default=3, help="lines between a sink and a truth line")
    s.add_argument("--any-cwe", action="store_true", help="count hits by alerts of any CWE")
    s.set_defaults(func=cmd_bench)

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
        a.cmd
        in (
            "context",
            "triage",
            "eval",
            "prune",
            "diagnose",
            "sweep",
            "variants",
            "confirm",
            "ml-dataset",
            "ml-predict",
        )
        and a.alerts is None
    ):
        a.alerts = [a.data_dir / "alerts.jsonl"]
    if a.cmd == "confirm" and a.out is None:
        a.out = a.data_dir / "confirm.jsonl"
    if a.cmd == "sweep" and a.out is None:
        a.out = a.data_dir / "sweep.jsonl"
    if a.cmd in ("triage", "prune", "ml-predict") and a.out is None:
        a.out = a.data_dir / "triage.jsonl"
    a.func(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
