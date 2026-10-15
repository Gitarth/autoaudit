"""
The learned-triage dataset: one JSON line per alert.

    {"alert_id", "project", "rule_id", "cwes", "path", "line",
     "label": true | false | null, "label_source", "group",
     "features": {...}, "graph": {"x": [[...]], "e": [[src, dst, type]]}}

Labels come from, in order of trust: hand labels (`alert_id,label` CSV),
OWASP Benchmark expected results, or earlier triage verdicts (LLM or prune;
`uncertain` is never used as a label). Alerts without a label are kept with
`label: null` so the same file can be scored by `ml-predict`.
"""

from __future__ import annotations

import gzip
import json
import logging
from pathlib import Path

from ..alerts import Alert
from ..codeindex import CodeIndex
from .features import features, slice_group
from .graph import build_graph

log = logging.getLogger(__name__)


def labels_from_triage(records: dict[str, dict]) -> dict[str, bool]:
    out = {}
    for aid, r in records.items():
        if r.get("verdict") == "true_positive":
            out[aid] = True
        elif r.get("verdict") == "false_positive":
            out[aid] = False
    return out


def example(
    alert: Alert,
    index: CodeIndex,
    label: bool | None = None,
    label_source: str | None = None,
    graph: bool = True,
    prune_feature: bool = True,
    group: str = "slice",
) -> dict:
    g = {
        "slice": lambda: slice_group(alert, index),
        "file": lambda: f"{alert.project}/{alert.path}",
        "project": lambda: alert.project,
        "cwe": lambda: (alert.cwes or [alert.rule_id])[0],
    }[group]()
    rec = {
        "alert_id": alert.id,
        "project": alert.project,
        "rule_id": alert.rule_id,
        "cwes": alert.cwes,
        "path": alert.path,
        "line": alert.line,
        "label": label,
        "label_source": label_source,
        "group": g,
        "features": features(alert, index, prune=prune_feature),
    }
    if graph:
        rec["graph"] = build_graph(alert, index)
    return rec


def build(
    found: list[Alert],
    root_of,
    labels: dict[str, tuple[bool, str]],
    graph: bool = True,
    group: str = "slice",
    only_labeled: bool = False,
) -> list[dict]:
    """`labels`: alert id -> (label, source). `root_of(project)` -> source root."""
    indexes: dict[str, CodeIndex] = {}
    out = []
    for a in found:
        lab = labels.get(a.id)
        if only_labeled and lab is None:
            continue
        if a.project not in indexes:
            indexes[a.project] = CodeIndex(root_of(a.project))
        rec = example(a, indexes[a.project], *(lab or (None, None)), graph=graph, group=group)
        if graph and rec["graph"] is None:
            log.debug("no graph for %s:%s", a.path, a.line)
        out.append(rec)
    return out


def _open(path: Path, mode: str):
    return (
        gzip.open(path, mode + "t", encoding="utf-8")
        if path.suffix == ".gz"
        else open(path, mode, encoding="utf-8")
    )


def write(records: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _open(path, "w") as fh:
        for r in records:
            fh.write(json.dumps(r, separators=(",", ":")) + "\n")


def read(path: Path) -> list[dict]:
    with _open(path, "r") as fh:
        return [json.loads(line) for line in fh if line.strip()]
