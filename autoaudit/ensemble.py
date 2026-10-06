"""
Run several analyzers and combine their alerts.

Different engines miss different things, so the union raises recall; where
they agree, that agreement is a confidence signal. Alerts from all tools are
normalised through SARIF (alerts.py), then:

- merge(): alerts at the same sink line with overlapping CWEs become one
  alert; the one with a flow (else the first tool) is kept and the others are
  recorded in `also_reported_by`;
- attach_flows(): alerts without a flow (e.g. Semgrep CE, which reports no
  traces) get approximate source-to-sink chains from lighttaint, so the AST
  feasibility checks and the triage context work for them too.

run_opengrep() runs Opengrep (or Semgrep CE) with autoaudit's own rules.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

from .alerts import Alert, Step
from .codeindex import CodeIndex

log = logging.getLogger(__name__)

RULES_DIR = Path(__file__).parent / "rules"
TOOL_PRIORITY = ("autoaudit-joern", "CodeQL", "Opengrep", "Semgrep OSS", "Semgrep", "autoaudit-sweep")


def run_opengrep(
    src: Path, out: Path, config: Path | None = None, binary: str | None = None, timeout: int | None = None
) -> Path:
    """Scan `src` with Opengrep/Semgrep CE; writes SARIF with paths relative to `src`."""
    binary = binary or shutil.which("opengrep") or shutil.which("semgrep")
    if not binary:
        raise RuntimeError("neither opengrep nor semgrep is installed")
    config = config or RULES_DIR
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        binary,
        "scan",
        "--config",
        str(Path(config).resolve()),
        "--sarif",
        "--quiet",
        "--output",
        str(out.resolve()),
        ".",
    ]
    if Path(binary).name.startswith("semgrep"):
        cmd.insert(2, "--metrics=off")  # never send telemetry from a client's code base
    # No network from a client's code base: no telemetry, no version check, no registry.
    env = {
        **os.environ,
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "OPENGREP_SEND_METRICS": "off",
        "OPENGREP_ENABLE_VERSION_CHECK": "0",
    }
    proc = subprocess.run(cmd, cwd=src, capture_output=True, text=True, timeout=timeout, env=env)
    if proc.returncode not in (0, 1) or not out.exists():  # 1 = findings present
        raise RuntimeError(f"{Path(binary).name} failed ({proc.returncode}): {proc.stderr.strip()[-800:]}")
    return out


def _rank(a: Alert) -> tuple:
    tool = TOOL_PRIORITY.index(a.tool) if a.tool in TOOL_PRIORITY else len(TOOL_PRIORITY)
    return (0 if a.flow else 1, tool)


def merge(alerts: list[Alert]) -> list[Alert]:
    """One alert per (project, file, sink line, overlapping CWE); agreement is recorded."""
    groups: list[list[Alert]] = []
    index: dict[tuple, list[list[Alert]]] = {}
    for a in alerts:
        key = (a.project, a.path, a.line)
        placed = False
        for g in index.get(key, []):
            if not a.cwes or not g[0].cwes or set(a.cwes) & {c for x in g for c in x.cwes}:
                g.append(a)
                placed = True
                break
        if not placed:
            g = [a]
            groups.append(g)
            index.setdefault(key, []).append(g)
    out = []
    for g in groups:
        g.sort(key=_rank)
        primary = g[0]
        others = sorted({f"{x.tool}:{x.rule_id}" for x in g[1:] if x.tool != primary.tool})
        primary.also_reported_by = sorted(set(primary.also_reported_by) | set(others))
        # Keep every merged path: feasibility pruning needs all of them to be dead.
        paths = [tuple((s.path, s.line) for s in f) for f in primary.flows]
        for x in g[1:]:
            for f in x.flows:
                sig = tuple((s.path, s.line) for s in f)
                if f and sig not in paths:
                    paths.append(sig)
                    if primary.flow:
                        primary.alt_flows.append(f)
                    else:
                        primary.flow = f
        for x in g[1:]:
            for c in x.cwes:
                if c not in primary.cwes:
                    primary.cwes.append(c)
        out.append(primary)
    return out


def attach_flows(alerts: list[Alert], spec: dict, indexes: dict[str, CodeIndex]) -> int:
    """Give flow-less alerts approximate chains from lighttaint; returns how many got one."""
    from .lighttaint import LightTaint

    rule_for_cwe = {r.get("cwe"): r["id"] for r in spec["rules"] if r.get("cwe")}
    engines: dict[tuple[str, str | None], LightTaint] = {}
    done = 0
    for a in alerts:
        if a.flow or a.project not in indexes or not a.line:
            continue
        rule = next((rule_for_cwe[c] for c in a.cwes if c in rule_for_cwe), None)
        key = (a.project, rule)
        if key not in engines:
            engines[key] = LightTaint(indexes[a.project], spec, rule)
        found = engines[key].sink_flows(a.path, a.line)
        if not found:
            continue
        chains = [[Step(a.path, ln) for ln in c] for c in found[1] if c]
        if chains:
            a.flow, a.alt_flows = chains[0], chains[1:]
            done += 1
    return done
