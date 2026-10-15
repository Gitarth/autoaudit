"""
Mine training examples from many fixed vulnerabilities, one case at a time.

For each candidate case (a repository and the commit that fixed a known
vulnerability, e.g. from `osv.candidates`):

1. check out the commit before the fix and the fix itself (shallow);
2. derive the ground truth from the fix diff (`bench.derive_truth`);
3. scan both versions with Opengrep/Semgrep and autoaudit's rules;
4. label the alerts by comparing the versions (`bench.label`);
5. keep the case only if the vulnerability was **identified and fixed**: at
   least one alert reached the fixed code at the advisory's CWE and was gone
   after the fix. Its real alerts and up to `max_negatives` of its surviving
   alerts become training examples (features + code graph), written while the
   checkout still exists;
6. delete the checkouts.

Progress is appended to `<out>/cases.jsonl`, so an interrupted run resumes
where it stopped. Disk use stays at about one repository.
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import time
from pathlib import Path

from . import alerts as alerts_mod
from . import bench, ensemble
from .codeindex import CodeIndex

log = logging.getLogger(__name__)


def _done(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with open(path, encoding="utf-8") as fh:
        return {json.loads(line)["name"] for line in fh if line.strip()}


def _append(path: Path, rec: dict) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, separators=(",", ":")) + "\n")


def _order(cases: list[bench.Case], seed: str = "autoaudit") -> list[bench.Case]:
    """Deterministic shuffle, so any prefix of the run mixes languages and CWEs."""
    return sorted(cases, key=lambda c: hashlib.sha1(f"{seed}{c.name}".encode()).hexdigest())


def mine_case(
    case: bench.Case,
    work: Path,
    out: Path,
    timeout: int = 900,
    max_negatives: int = 30,
    max_source_files: int = 15,
    tolerance: int = 3,
) -> tuple[dict, list[dict]]:
    """(progress record, training examples). Writes nothing outside `work`."""
    from .ml import data

    t0 = time.time()
    recs: list[dict] = []
    res: dict = {
        "name": case.name,
        "repo": case.repo,
        "fix": case.fix,
        "cwe": case.cwe,
        "language": case.language,
    }
    vuln_dir, fixed_dir = work / "repos" / case.name, work / "fixed" / case.name
    try:
        vuln = bench.checkout(case, vuln_dir, timeout)
        locs = bench.derive_truth(case, vuln_dir, vuln)
        res["truth_files"] = len(locs)
        if not locs:
            res["status"] = "no_source_truth"
            return res, recs
        if len(locs) > max_source_files:
            res["status"] = "fix_too_large"
            return res, recs
        bench.checkout_fixed(case, vuln_dir, fixed_dir, timeout)
        truth = {case.name: {"cwe": case.cwe, "locations": [loc.__dict__ for loc in locs]}}
        found = {}
        for version, src in (("vulnerable", vuln_dir), ("fixed", fixed_dir)):
            sarif = work / f"{case.name}.{version}.sarif"
            ensemble.run_opengrep(src, sarif, None, None, timeout)
            found[version] = alerts_mod.read_sarif(sarif, project=case.name)
            sarif.unlink(missing_ok=True)
        res["alerts"] = len(found["vulnerable"])
        labels, stats = bench.label(
            truth, found["vulnerable"], found["fixed"], work / "repos", work / "fixed", {case.name}, tolerance
        )
        st = stats.get(case.name, {"real": 0, "false": 0})
        res.update(real=st["real"], weak_false=st["false"])
        if not st["real"]:
            res["status"] = "not_identified"
            return res, recs
        # every real alert, and a deterministic sample of the surviving ones,
        # same-CWE first (the hardest negatives)
        by_id = {a.id: a for a in found["vulnerable"]}
        real = [by_id[i] for i, (lab, _) in labels.items() if lab]
        negs = sorted(
            (by_id[i] for i, (lab, _) in labels.items() if not lab),
            key=lambda a: (case.cwe not in a.cwes, hashlib.sha1(a.id.encode()).hexdigest()),
        )[:max_negatives]
        index = CodeIndex(vuln_dir)
        for a in real + negs:
            lab, source = labels[a.id]
            rec = data.example(a, index, lab, source)
            rec.update(group=case.repo, language=case.language, case=case.name, advisory_cwe=case.cwe)
            recs.append(rec)
        res["_alerts"] = [a.to_dict() for a in real + negs]
        res.update(status="identified", examples=len(recs))
        return res, recs
    except Exception as err:  # unreachable repo, scanner crash, timeout: record and move on
        res["status"] = "error"
        res["error"] = (str(err).splitlines() or [type(err).__name__])[0][:300]
        return res, recs
    finally:
        res["seconds"] = round(time.time() - t0, 1)
        if vuln_dir.exists():
            # the fixed tree is a worktree of the vulnerable checkout
            shutil.rmtree(fixed_dir, ignore_errors=True)
            shutil.rmtree(vuln_dir, ignore_errors=True)


def _run(args) -> tuple[dict, list[dict]]:
    case, work, timeout, max_negatives = args
    return mine_case(case, work, Path("."), timeout, max_negatives)


def mine(
    cases: list[bench.Case],
    out: Path,
    limit: int | None = None,
    timeout: int = 900,
    max_negatives: int = 30,
    max_hours: float | None = None,
    workers: int = 1,
) -> dict:
    from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait

    out.mkdir(parents=True, exist_ok=True)
    (out / "alerts").mkdir(exist_ok=True)
    progress = out / "cases.jsonl"
    done = _done(progress)
    todo = [c for c in _order(cases) if c.name not in done]
    if limit is not None:
        todo = todo[:limit]
    deadline = time.time() + max_hours * 3600 if max_hours else None
    queue = list(enumerate(todo, 1))
    # each worker scans into its own directory; only this process writes the outputs
    with ProcessPoolExecutor(max_workers=max(1, workers)) as pool:
        running: dict = {}
        slots = list(range(max(1, workers)))
        while queue or running:
            while queue and slots and not (deadline and time.time() > deadline):
                i, case = queue.pop(0)
                slot = slots.pop()
                fut = pool.submit(_run, (case, out / f"work{slot}", timeout, max_negatives))
                running[fut] = (i, case, slot)
            if not running:
                break
            finished, _ = wait(running, return_when=FIRST_COMPLETED)
            for fut in finished:
                i, case, slot = running.pop(fut)
                slots.append(slot)
                try:
                    res, recs = fut.result()
                except Exception as err:  # a crashed worker process
                    res, recs = {"name": case.name, "status": "error", "error": str(err)[:300]}, []
                found = res.pop("_alerts", None)
                if recs:
                    with open(out / "dataset.jsonl", "a", encoding="utf-8") as fh:
                        for r in recs:
                            fh.write(json.dumps(r, separators=(",", ":")) + "\n")
                if found:
                    with open(out / "alerts" / f"{case.name}.jsonl", "w", encoding="utf-8") as fh:
                        for d in found:
                            fh.write(json.dumps(d) + "\n")
                _append(progress, res)
                log.info(
                    "[%d/%d] %s %s %s: %s (%s real, %ss)",
                    i,
                    len(todo),
                    case.language,
                    case.cwe,
                    case.name,
                    res.get("status"),
                    res.get("real", "-"),
                    res.get("seconds"),
                )
    return summary(out)


def summary(out: Path) -> dict:
    from collections import Counter

    rows = []
    if (out / "cases.jsonl").exists():
        with open(out / "cases.jsonl", encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
    ident = [r for r in rows if r.get("status") == "identified"]
    return {
        "cases_tried": len(rows),
        "status": dict(Counter(r.get("status") for r in rows)),
        "identified_by_language": dict(Counter(r.get("language") for r in ident)),
        "identified_by_cwe": dict(Counter(r.get("cwe") for r in ident)),
        "real_examples": sum(r.get("real", 0) for r in ident),
        "examples": sum(r.get("examples", 0) for r in ident),
        "dataset": str(out / "dataset.jsonl"),
    }
