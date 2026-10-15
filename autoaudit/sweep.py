"""
Sink sweep: dangerous calls that no reported flow reaches.

Taint tracking misses flows it cannot follow (reflection, dependency
injection, framework callbacks, engine limitations). A reviewer compensates by
looking at every dangerous call and asking "can attacker data get here?". This
module lists the sink call sites of every rule (exported by Joern), drops the
ones that are already alerted or provably harmless (all watched arguments are
literals, every argument is a constant by AST evaluation, or the call is in
dead code), and turns the rest into flow-less alerts for (agent) triage.
"""

from __future__ import annotations

import json
from pathlib import Path

from .alerts import Alert, Step
from .codeindex import CodeIndex, enclosing_function, walk
from .feasibility import UNKNOWN, constants, dead_lines, evaluate

TOOL = "autoaudit-sweep"
MESSAGE = (
    "Dangerous call with non-constant input that no source-to-sink flow reaches. "
    "Decide whether attacker-controlled data can reach its arguments."
)


def read_sinks(paths: list[Path]) -> list[dict]:
    out = []
    for p in paths:
        project = Path(p).name.removesuffix(".sinks.jsonl")
        for line in Path(p).read_text(encoding="utf-8").splitlines():
            if line.strip():
                d = json.loads(line)
                d["project"] = project
                out.append(d)
    return out


def _call_on_line(p, fn, line: int, code: str):
    """The call node on `line` whose text matches the sink code best."""
    want = " ".join(code.split())
    best = None
    for n in walk(fn):
        if n.start_point[0] + 1 == line and n.type in p.spec.calls:
            text = " ".join(p.text(n).split())
            if text == want:
                return n
            if best is None and (want.startswith(text) or text.startswith(want[:40])):
                best = n
    return best


def _harmless(index: CodeIndex, path: str, line: int, code: str, cache: dict) -> str | None:
    p = index.parsed(path)
    fn = enclosing_function(p, line) if p is not None and line else None
    if fn is None:
        return None
    key = (path, fn.start_byte)
    if key not in cache:
        cache[key] = (constants(p, fn), dead_lines(p, fn))
    env, dead = cache[key]
    if line in dead:
        return "dead code"
    call = _call_on_line(p, fn, line, code)
    args = call.child_by_field_name("arguments") if call is not None else None
    if (
        args is not None
        and args.named_child_count
        and all(evaluate(p, a, env) is not UNKNOWN for a in args.named_children if a.type != "comment")
    ):
        return "constant arguments"
    return None


def sweep(
    sinks: list[dict],
    alerts: list[Alert],
    spec: dict,
    indexes: dict[str, CodeIndex],
    require_taint: bool = True,
) -> tuple[list[Alert], dict]:
    """require_taint: keep only sinks whose arguments syntactically derive from user input
    (see lighttaint); without it every non-constant sink becomes an alert."""
    from .lighttaint import LightTaint

    light: dict[tuple[str, str], LightTaint] = {}
    cwe_of = {r["id"]: r.get("cwe") for r in spec["rules"]}
    name_of = {r["id"]: r.get("name", r["id"]) for r in spec["rules"]}
    alerted = {(a.project, a.path, a.line, a.rule_id) for a in alerts}
    alerted_cwe = {(a.project, a.path, a.line, c) for a in alerts for c in a.cwes}
    stats = {
        "sink_sites": len(sinks),
        "already_alerted": 0,
        "literal": 0,
        "constant arguments": 0,
        "dead code": 0,
        "no user input in arguments": 0,
        "new_alerts": 0,
    }
    out, seen, cache = [], set(), {}
    for s in sinks:
        key = (s["project"], s["file"], s["line"], s["rule"])
        cwe = cwe_of.get(s["rule"])
        if key in alerted or (cwe and (s["project"], s["file"], s["line"], cwe) in alerted_cwe):
            stats["already_alerted"] += 1
            continue
        if key in seen:
            continue
        seen.add(key)
        if s.get("literal_args"):
            stats["literal"] += 1
            continue
        index = indexes.get(s["project"])
        why = _harmless(index, s["file"], s["line"], s.get("code", ""), cache) if index else None
        if why:
            stats[why] += 1
            continue
        hits, chains = None, []
        if require_taint:
            lt = None
            if s["project"] in indexes:
                key_lt = (s["project"], s["rule"])
                if key_lt not in light:
                    light[key_lt] = LightTaint(indexes[s["project"]], spec, s["rule"])
                lt = light[key_lt]
            found = lt.sink_flows(s["file"], s["line"]) if lt else None
            if not found:
                stats["no user input in arguments"] += 1
                continue
            hits, chains = found
        detail = (
            f" Arguments use {', '.join(f'`{h}`' for h in hits[:5])}, which may derive from user input."
            if hits
            else ""
        )
        flows = [[Step(s["file"], ln) for ln in c] for c in chains if c]
        out.append(
            Alert(
                tool=TOOL,
                rule_id=s["rule"],
                message=f"{name_of.get(s['rule'], s['rule'])}: {MESSAGE}{detail}",
                project=s["project"],
                path=s["file"],
                line=s["line"],
                function=s.get("method"),
                severity="note",
                cwes=[cwe] if cwe else [],
                flow=flows[0] if flows else [],
                alt_flows=flows[1:],
            )
        )
        stats["new_alerts"] += 1
    return out, stats
