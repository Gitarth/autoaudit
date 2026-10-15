"""
Benchmark on real projects with known, fixed vulnerabilities.

A corpus (JSON, see autoaudit/corpus/java-cves.json) lists cases: a git
repository, the commit that fixed a vulnerability and its CWE. `fetch` checks
each project out at the commit just before the fix (or `vulnerable`, if given)
and derives the ground truth from the fix itself:

- the lines the fix deleted or changed, in the vulnerable version; for a pure
  insertion, the lines on either side of it. Imports, package lines, blank
  lines and test files are ignored;
- the functions containing those lines (needs the `ast` extra);
- optional hand-written `locations` ({"path", "lines"}) for fixes that sit
  away from the vulnerable flow (e.g. a patched blacklist).

`score` then asks, per case, whether an alert hit it, at three strictnesses:

- sink_line: the alert's sink is within `tolerance` lines of a truth line;
- sink_function: the sink is inside a function the fix touched;
- flow: any step of any reported path is (a fix guards the flow it patches).

An alert counts only if one of its CWEs is the case's CWE, unless
`any_cwe=True`. Every other alert on the project is counted as noise.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .alerts import Alert
from .evaluate import kept

log = logging.getLogger(__name__)

DEFAULT_CORPUS = Path(__file__).parent / "corpus" / "java-cves.json"
SOURCE_EXT = {
    ".java", ".kt", ".scala", ".groovy", ".py", ".js", ".jsx", ".ts", ".tsx",
    ".go", ".php", ".cs", ".rb", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift",
}  # fmt: skip
_TEST_PATH = re.compile(r"(^|/)(src/test|tests?|__tests__|testing)/|(Tests?|_test|Spec)\.\w+$", re.I)
_NOISE_LINE = re.compile(r"^\s*(import\s|package\s|$|[{}]\s*$|//|\*|/\*)")
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@")
_NAME = re.compile(r"[A-Za-z0-9_-]+")
LEVELS = ("sink_line", "sink_function", "flow")


@dataclass
class Case:
    name: str
    repo: str
    fix: str
    cwe: str
    id: str | None = None
    vulnerable: str | None = None  # default: the fix commit's first parent
    license: str | None = None
    summary: str | None = None
    locations: list[dict] = field(default_factory=list)
    language: str | None = None
    advisory: str | None = None


@dataclass
class Location:
    path: str
    lines: list[int]
    functions: list[list] = field(default_factory=list)  # [start, end, name]


def load_corpus(path: Path = DEFAULT_CORPUS) -> list[Case]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    cases = []
    for c in doc["cases"]:
        c = {k: v for k, v in c.items() if k in Case.__dataclass_fields__}
        cwe = str(c["cwe"]).upper()
        c["cwe"] = cwe if cwe.startswith("CWE-") else f"CWE-{int(cwe)}"
        cases.append(Case(**c))
    names = [c.name for c in cases]
    if bad := [n for n in names if not _NAME.fullmatch(n)]:
        raise ValueError(f"case names may only use letters, digits, - and _ (no dots): {bad}")
    if len(names) != len(set(names)):
        raise ValueError("case names must be unique (they name the checkout directory)")
    return cases


# ------------------------------------------------------------------- git
def _git(*args: str, cwd: Path, timeout: int | None = None) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} failed: {proc.stderr.strip()[-500:]}")
    return proc.stdout


def checkout(case: Case, dest: Path, timeout: int | None = None) -> str:
    """Shallow checkout of the vulnerable commit (plus the fix, for the diff);
    returns the vulnerable SHA. Safe to re-run: fetches are incremental."""
    dest.mkdir(parents=True, exist_ok=True)
    if not (dest / ".git").exists():
        _git("init", "-q", cwd=dest)
        _git("remote", "add", "origin", case.repo, cwd=dest)
    elif _git("remote", "get-url", "origin", cwd=dest).strip() != case.repo:
        raise RuntimeError(f"{dest} is a checkout of another repository")
    # depth 2 brings the fix and its parent; GitHub serves any commit by SHA.
    _git("fetch", "-q", "--depth", "2", "origin", case.fix, cwd=dest, timeout=timeout)
    vuln = case.vulnerable or _git("rev-parse", f"{case.fix}^1", cwd=dest).strip()
    if case.vulnerable:
        _git("fetch", "-q", "--depth", "1", "origin", vuln, cwd=dest, timeout=timeout)
    _git("-c", "advice.detachedHead=false", "checkout", "-q", "--force", "--detach", vuln, cwd=dest)
    return vuln


def checkout_fixed(case: Case, src: Path, dest: Path, timeout: int | None = None) -> None:
    """Second working tree of `src` at the fix commit (fetched by `checkout`)."""
    if (dest / ".git").exists():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    _git("fetch", "-q", "--depth", "2", "origin", case.fix, cwd=src, timeout=timeout)
    _git("worktree", "add", "-q", "--force", "--detach", str(dest.resolve()), case.fix, cwd=src)


# ------------------------------------------------------------ ground truth
def is_source(path: str) -> bool:
    return Path(path).suffix.lower() in SOURCE_EXT and not _TEST_PATH.search(path)


@dataclass
class Hunk:
    start: int  # first old line changed; for a pure insertion, the old line it follows
    count: int  # old lines deleted or changed (0: pure insertion)
    added: list[str] = field(default_factory=list)


def hunks(diff: str) -> dict[str, list[Hunk]]:
    """Old-side hunks of a `git diff -U0`, per old path (new files are skipped)."""
    out: dict[str, list[Hunk]] = {}
    path, cur, header = None, None, False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            path, cur, header = None, None, True
        elif header and line.startswith("--- "):
            old = line[4:].strip()
            path = None if old == "/dev/null" else old[2:] if old.startswith("a/") else old
        elif m := _HUNK.match(line):
            header = False
            cur = Hunk(int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1))
            if path:
                out.setdefault(path, []).append(cur)
        elif cur is not None and not header and line.startswith("+"):
            cur.added.append(line[1:])
    return out


def truth_lines(hunk: Hunk, text: list[str]) -> set[int]:
    """The vulnerable-version code lines a hunk stands for: the code it deleted or
    changed; if it only inserted code (or replaced blank lines), the nearest code
    line on either side. Imports, blank lines, braces and comments never count."""

    def code(n: int) -> bool:
        return 1 <= n <= len(text) and not _NOISE_LINE.match(text[n - 1])

    old = {n for n in range(hunk.start, hunk.start + hunk.count) if code(n)}
    if old or all(_NOISE_LINE.match(a) for a in hunk.added):
        return old
    before = hunk.start if hunk.count == 0 else hunk.start - 1
    after = before + 1 + hunk.count
    out = set()
    for n in range(before, before - 4, -1):
        if code(n):
            out.add(n)
            break
    for n in range(after, after + 4):
        if code(n):
            out.add(n)
            break
    return out


def derive_truth(case: Case, src: Path, vuln: str) -> list[Location]:
    diff = _git("diff", "-U0", "--no-color", "--no-renames", vuln, case.fix, cwd=src)
    touched: dict[str, set[int]] = {}
    for path, hs in hunks(diff).items():
        file = src / path
        if not is_source(path) or not file.exists():
            continue
        text = file.read_text(encoding="utf-8", errors="replace").split("\n")
        lines = set().union(*(truth_lines(h, text) for h in hs))
        if lines:
            touched[path] = lines
    for loc in case.locations:  # hand-written truth, e.g. the real sink of a blacklist bypass
        touched.setdefault(loc["path"], set()).update(int(n) for n in loc["lines"])

    index = None
    try:
        from . import codeindex

        if codeindex.available():
            index = codeindex.CodeIndex(src, strip=False)
    except Exception as err:  # function spans are a bonus, never block the benchmark
        log.warning("%s: no function spans (%s)", case.name, err)

    locations = []
    for path, lines in sorted(touched.items()):
        spans = {index.function_span(path, n) for n in lines} - {None} if index else set()
        locations.append(Location(path, sorted(lines), [list(sp) for sp in sorted(spans)]))
    return locations


def fetch(cases: list[Case], root: Path, timeout: int | None = None) -> dict:
    """Check out every case under root/repos/<name> and write root/truth.json."""
    truth_path = root / "truth.json"
    truth = json.loads(truth_path.read_text()) if truth_path.exists() else {}
    for case in cases:
        src = root / "repos" / case.name
        try:
            vuln = checkout(case, src, timeout)
            locs = derive_truth(case, src, vuln)
        except Exception as err:  # one unreachable repo must not stop the rest
            log.error("%s: %s", case.name, err)
            truth[case.name] = {"error": str(err).splitlines()[0]}
            continue
        if not locs:
            log.warning("%s: the fix touches no source lines; add `locations` to the case", case.name)
        truth[case.name] = {
            "id": case.id,
            "cwe": case.cwe,
            "repo": case.repo,
            "fix": case.fix,
            "vulnerable": vuln,
            "locations": [loc.__dict__ for loc in locs],
        }
        log.info("%s @ %s: %d truth lines", case.name, vuln[:10], sum(len(x.lines) for x in locs))
    root.mkdir(parents=True, exist_ok=True)
    truth_path.write_text(json.dumps(truth, indent=2), encoding="utf-8")
    return truth


# ----------------------------------------------------------------- scoring
def _same_file(alert_path: str, truth_path: str) -> bool:
    a = alert_path.replace("\\", "/").lstrip("/")
    return a == truth_path or a.endswith("/" + truth_path) or truth_path.endswith("/" + a)


def _hits(path: str, line: int | None, loc: dict, tolerance: int) -> tuple[bool, bool]:
    """(near a truth line, inside a touched function)"""
    if line is None or not _same_file(path, loc["path"]):
        return False, False
    near = any(abs(line - n) <= tolerance for n in loc["lines"])
    inside = any(s <= line <= e for s, e, _ in loc.get("functions", []))
    return near, inside


def match(alert: Alert, locations: list[dict], tolerance: int = 3) -> set[str]:
    """Which LEVELS this alert reaches for one case."""
    levels = set()
    for loc in locations:
        near, inside = _hits(alert.path, alert.line, loc, tolerance)
        if near:
            levels.add("sink_line")
        if near or inside:
            levels.add("sink_function")
        for flow in alert.flows:
            for step in flow:
                if any(_hits(step.path, step.line, loc, tolerance)):
                    levels.add("flow")
    if levels:
        levels.add("flow")  # a sink hit is also a hit on the flow
    return levels


def score(
    truth: dict,
    alerts: list[Alert],
    triage: dict[str, dict] | None = None,
    keep_uncertain: bool = True,
    tolerance: int = 3,
    any_cwe: bool = False,
) -> dict:
    by_project: dict[str, list[Alert]] = {}
    for a in alerts:
        by_project.setdefault(a.project, []).append(a)

    cases, totals = [], {lvl: 0 for lvl in LEVELS}
    totals_triaged = {lvl: 0 for lvl in LEVELS}
    scored = 0
    for name, t in truth.items():
        if "error" in t:
            cases.append({"name": name, "error": t["error"]})
            continue
        scored += 1
        project = by_project.get(name, [])
        hits: dict[str, set[str]] = {}
        for a in project:
            if not any_cwe and t["cwe"] not in a.cwes:
                continue
            levels = match(a, t["locations"], tolerance)
            if levels:
                hits[a.id] = levels
        detected = {lvl: any(lvl in v for v in hits.values()) for lvl in LEVELS}
        row = {
            "name": name,
            "id": t.get("id"),
            "cwe": t["cwe"],
            "alerts": len(project),
            "alerts_same_cwe": sum(1 for a in project if t["cwe"] in a.cwes),
            "detected": detected,
            "hits": {aid: sorted(v) for aid, v in hits.items()},
        }
        for lvl in LEVELS:
            totals[lvl] += detected[lvl]
        if triage is not None:
            survivors = {a.id for a in project if kept(a, triage, keep_uncertain)}
            row["alerts_after_triage"] = len(survivors)
            row["detected_after_triage"] = {
                lvl: any(lvl in v for aid, v in hits.items() if aid in survivors) for lvl in LEVELS
            }
            for lvl in LEVELS:
                totals_triaged[lvl] += row["detected_after_triage"][lvl]
        cases.append(row)

    summary = {
        "cases": scored,
        "detected": totals,
        "recall": {lvl: round(totals[lvl] / scored, 3) if scored else None for lvl in LEVELS},
        "alerts": sum(c.get("alerts", 0) for c in cases),
    }
    if triage is not None:
        summary["detected_after_triage"] = totals_triaged
        summary["alerts_after_triage"] = sum(c.get("alerts_after_triage", 0) for c in cases)
    return {"summary": summary, "cases": cases}


# ---------------------------------------------------------------- labels
def _line(root: Path, path: str | None, line: int | None) -> str:
    """Whitespace-normalised source line, '' if unavailable."""
    if not path or not line:
        return ""
    try:
        text = (root / path).read_text(encoding="utf-8", errors="replace").split("\n")
    except OSError:
        return ""
    return " ".join(text[line - 1].split()) if 0 < line <= len(text) else ""


def persistence_key(a: Alert, root: Path) -> tuple:
    """What identifies a finding across two versions of a project when line numbers
    move: rule, sink file and code, source file and code."""
    src = a.flow[0] if a.flow else None
    return (
        a.rule_id,
        a.path,
        _line(root, a.path, a.line),
        src.path if src else None,
        _line(root, src.path, src.line) if src else "",
    )


def label(
    truth: dict,
    vulnerable: list[Alert],
    fixed: list[Alert],
    vuln_root: Path,
    fixed_root: Path,
    scanned_fixed: set[str],
    tolerance: int = 3,
    weak_negatives: bool = True,
) -> tuple[dict[str, tuple[bool, str]], dict]:
    """Differential labels for the alerts on vulnerable checkouts (after D2A,
    Zheng et al., ICSE-SEIP 2021):

    - real (`fix`): reaches the fixed code (sink or flow, at the case's CWE)
      and is gone after the fix;
    - false (`persists`, weak): does not touch the fixed code and is still
      reported, with the same sink and source code, after the fix. Most such
      alerts are false positives, but some may be other, unfixed bugs;
    - unlabeled: everything else (touches the fix but survives it, or vanishes
      for an unrelated reason).

    `vuln_root / <case>` and `fixed_root / <case>` are the two checkouts;
    `scanned_fixed` names the cases whose fixed version was scanned (with or
    without alerts). Cases missing from it get no labels."""
    by_case_fixed: dict[str, set] = {name: set() for name in scanned_fixed}
    for a in fixed:
        if a.project in by_case_fixed:
            by_case_fixed[a.project].add(persistence_key(a, fixed_root / a.project))
    labels: dict[str, tuple[bool, str]] = {}
    stats: dict[str, dict] = {}
    for a in vulnerable:
        t = truth.get(a.project)
        if not t or "error" in t or a.project not in by_case_fixed:
            continue
        st = stats.setdefault(a.project, {"alerts": 0, "real": 0, "false": 0, "unlabeled": 0})
        st["alerts"] += 1
        hit = t["cwe"] in a.cwes and bool(match(a, t["locations"], tolerance))
        touches = bool(match(a, t["locations"], tolerance))
        persists = persistence_key(a, vuln_root / a.project) in by_case_fixed[a.project]
        if hit and not persists:
            labels[a.id] = (True, "fix")
            st["real"] += 1
        elif weak_negatives and not touches and persists:
            labels[a.id] = (False, "persists")
            st["false"] += 1
        else:
            st["unlabeled"] += 1
    return labels, stats


def markdown(report: dict) -> str:
    """The scorecard as a Markdown table (detection = flow level)."""
    triaged = "detected_after_triage" in report["summary"]
    head = "| case | id | CWE | alerts | same CWE | sink line | sink fn | flow |"
    sep = "|---|---|---|---|---|---|---|---|"
    if triaged:
        head += " after triage |"
        sep += "---|"
    rows = [head, sep]
    for c in report["cases"]:
        if "error" in c:
            rows.append(f"| {c['name']} | error: {c['error']} |" + " |" * (6 + triaged))
            continue
        d = c["detected"]
        mark = {True: "yes", False: "-"}
        row = (
            f"| {c['name']} | {c['id'] or ''} | {c['cwe']} | {c['alerts']} | {c['alerts_same_cwe']} "
            f"| {mark[d['sink_line']]} | {mark[d['sink_function']]} | {mark[d['flow']]} |"
        )
        if triaged:
            row += f" {mark[c['detected_after_triage']['flow']]} ({c['alerts_after_triage']} kept) |"
        rows.append(row)
    s = report["summary"]
    rows.append("")
    rows.append(
        f"Detected {s['detected']['flow']}/{s['cases']} (flow), {s['detected']['sink_function']}"
        f"/{s['cases']} (sink function), {s['detected']['sink_line']}/{s['cases']} (sink line) "
        f"with {s['alerts']} alerts."
    )
    return "\n".join(rows) + "\n"
