"""
Language-agnostic taint analysis with Joern (Apache-2.0, https://joern.io).

A *spec* says, per rule, where untrusted data comes from (sources), where it
becomes dangerous (sinks) and what neutralizes it (sanitizers). Specs are plain
JSON so they can be hand-written or generated per codebase by an LLM:

    {"rules": [{
        "id": "sqli", "name": "SQL injection", "cwe": "CWE-89", "severity": "error",
        "sources":    [{"kind": "call", "pattern": ".*getParameter.*"}],
        "sinks":      [{"pattern": "executeQuery|executeUpdate", "arg": "*"}],
        "sanitizers": [{"pattern": ".*escapeSql.*"}]
    }]}

Source kinds: "call" (return value of a matching call), "param" (parameters of
methods whose full name matches), "annotated_param" (parameters carrying a
matching annotation, e.g. Spring's RequestParam). Patterns are Java regexes
matched against a call's name and its fully qualified method name.

Flows are written as SARIF 2.1.0 so they feed the same pipeline as any other
analyzer.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)

HERE = Path(__file__).parent
SCRIPT = HERE / "taint.sc"
DEFAULT_SPEC = HERE.parent / "specs" / "java.json"
SOURCE_KINDS = {"call", "param", "annotated_param"}


class SpecError(ValueError):
    pass


def load_spec(path: Path) -> dict:
    spec = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_spec(spec)
    return spec


def validate_spec(spec: dict) -> None:
    rules = spec.get("rules")
    if not isinstance(rules, list) or not rules:
        raise SpecError("spec needs a non-empty 'rules' list")
    seen = set()
    for r in rules:
        rid = r.get("id")
        if not rid or not re.fullmatch(r"[\w.-]+", rid):
            raise SpecError(f"bad rule id: {rid!r}")
        if rid in seen:
            raise SpecError(f"duplicate rule id: {rid}")
        seen.add(rid)
        if not r.get("sources") or not r.get("sinks"):
            raise SpecError(f"{rid}: needs at least one source and one sink")
        for kind, items in (
            ("source", r["sources"]),
            ("sink", r["sinks"]),
            ("sanitizer", r.get("sanitizers", [])),
        ):
            for item in items:
                pat = item.get("pattern", "")
                if not pat or "\t" in pat or "\n" in pat:
                    raise SpecError(f"{rid}: empty or multi-line {kind} pattern")
                try:
                    re.compile(pat)
                except re.error as err:
                    raise SpecError(f"{rid}: invalid {kind} pattern {pat!r}: {err}") from err
                if kind == "source" and item.get("kind", "call") not in SOURCE_KINDS:
                    raise SpecError(f"{rid}: unknown source kind {item.get('kind')!r}")
                if kind == "sink":
                    arg = str(item.get("arg", "*"))
                    if arg != "*" and not arg.isdigit():
                        raise SpecError(f"{rid}: sink arg must be '*' or an index, got {arg!r}")


def spec_to_tsv(spec: dict) -> str:
    """The flat format taint.sc reads (avoids a JSON dependency in Scala)."""
    lines = []
    for r in spec["rules"]:
        for s in r["sources"]:
            lines.append(["SOURCE", r["id"], s.get("kind", "call"), s["pattern"]])
        for s in r["sinks"]:
            lines.append(["SINK", r["id"], "call", s["pattern"], str(s.get("arg", "*"))])
        for s in r.get("sanitizers", []):
            lines.append(["SANITIZER", r["id"], "call", s["pattern"]])
    return "\n".join("\t".join(cols) for cols in lines) + "\n"


# ------------------------------------------------------------------- running
def _bin(bin_dir: Path | None, name: str) -> str:
    if bin_dir:
        return str(Path(bin_dir) / name)
    env = os.environ.get("JOERN_HOME")
    return str(Path(env) / name) if env else name


def parse(
    src: Path, cpg: Path, bin_dir: Path | None = None, language: str | None = None, timeout: int | None = None
) -> None:
    """Build a code property graph with `joern-parse` (language auto-detected)."""
    cmd = [_bin(bin_dir, "joern-parse"), str(src), "--output", str(cpg)]
    if language:
        cmd += ["--language", language]
    _run(cmd, timeout)
    if not cpg.exists():
        raise RuntimeError(f"joern-parse produced no CPG for {src}")


def query(
    cpg: Path,
    spec: dict,
    bin_dir: Path | None = None,
    timeout: int | None = None,
    max_flows: int = 200,
    max_paths: int = 8,
    semantics: Path | None = None,
    externals_out: Path | None = None,
    sinks_out: Path | None = None,
) -> list[dict]:
    """Run taint.sc against a CPG and return the raw flows.
    semantics: extra library flow summaries (see taint.sc); externals_out / sinks_out: where to
    write the library methods seen on flows and every sink call site."""
    with tempfile.TemporaryDirectory(prefix="autoaudit-joern-") as tmp:
        tmp = Path(tmp)
        (tmp / "spec.tsv").write_text(spec_to_tsv(spec), encoding="utf-8")
        out = tmp / "flows.jsonl"
        cmd = [
            _bin(bin_dir, "joern"),
            "--script",
            str(SCRIPT),
            "--param",
            f"inputPath={cpg.resolve()}",
            "--param",
            f"specFile={tmp / 'spec.tsv'}",
            "--param",
            f"outFile={out}",
            "--param",
            f"maxFlows={max_flows}",
            "--param",
            f"maxPaths={max_paths}",
        ]
        # Joern's argument parser rejects empty values, so optional files are only passed when set.
        for name, value in (
            ("semanticsFile", semantics),
            ("externalsFile", externals_out),
            ("sinksFile", sinks_out),
        ):
            if value:
                cmd += ["--param", f"{name}={Path(value).resolve()}"]
        _run(cmd, timeout, cwd=tmp)  # Joern writes a workspace/ into the cwd
        if not out.exists():
            raise RuntimeError("Joern finished without writing flows")
        with open(out, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]


def _run(cmd: list[str], timeout: int | None, cwd: Path | None = None) -> None:
    log.debug("Running %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    for line in proc.stdout.splitlines():
        if line.startswith("[autoaudit]"):
            log.info(line)
    if proc.returncode:
        out = (proc.stderr or "") + "\n" + (proc.stdout or "")
        # report the exception messages, not the JVM stack frames
        useful = [
            ln
            for ln in out.splitlines()
            if ln.strip() and not ln.lstrip().startswith("at ") and "JAVA_TOOL_OPTIONS" not in ln
        ]
        tail = "\n".join(useful[-15:])
        raise RuntimeError(f"{Path(cmd[0]).name} failed ({proc.returncode}):\n{tail}")


# --------------------------------------------------------------------- SARIF
def to_sarif(flows: list[dict], spec: dict, tool_version: str = "") -> dict:
    rules = {r["id"]: r for r in spec["rules"]}
    driver_rules = []
    for r in spec["rules"]:
        tags = ["security"] + ([f"external/cwe/{r['cwe'].lower()}"] if r.get("cwe") else [])
        driver_rules.append(
            {
                "id": r["id"],
                "name": r.get("name", r["id"]),
                "shortDescription": {"text": r.get("name", r["id"])},
                "defaultConfiguration": {"level": r.get("severity", "warning")},
                "properties": {"tags": tags},
            }
        )

    def loc(step: dict) -> dict:
        region = {"startLine": step["line"]} if step.get("line") else {}
        method = step.get("method") or ""
        out = {"physicalLocation": {"artifactLocation": {"uri": step.get("file", "")}, "region": region}}
        if method and not method.startswith("<"):
            out["logicalLocations"] = [{"fullyQualifiedName": method}]
        return out

    def code_flow(steps: list[dict]) -> dict:
        return {
            "threadFlows": [
                {
                    "locations": [
                        {"location": {**loc(s), "message": {"text": s.get("code", "")}}} for s in steps
                    ]
                }
            ]
        }

    results = []
    for f in flows:
        paths = [p for p in (f.get("flows") or [f.get("flow") or []]) if p]
        if not paths:
            continue
        steps = paths[0]
        rule = rules.get(f["rule"], {"id": f["rule"]})
        src, sink = steps[0], steps[-1]
        results.append(
            {
                "ruleId": rule["id"],
                "level": rule.get("severity", "warning"),
                "message": {
                    "text": f"{rule.get('name', rule['id'])}: data from "
                    f"`{src.get('code', '?')}` (line {src.get('line')}) reaches "
                    f"`{sink.get('code', '?')}` (line {sink.get('line')})"
                },
                "locations": [loc(sink)],
                "codeFlows": [code_flow(p) for p in paths],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "autoaudit-joern",
                        "version": tool_version,
                        "informationUri": "https://joern.io",
                        "rules": driver_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def scan(
    src: Path,
    spec: dict,
    out_sarif: Path,
    work_dir: Path,
    bin_dir: Path | None = None,
    language: str | None = None,
    timeout: int | None = None,
    max_flows: int = 200,
    semantics: Path | None = None,
) -> int:
    """Parse + query one source tree; returns the number of flows found.
    `max_flows` caps flows per rule so one noisy rule cannot flood a large repo."""
    work_dir.mkdir(parents=True, exist_ok=True)
    cpg = work_dir / f"{out_sarif.stem}.cpg.bin"
    parse(src, cpg, bin_dir, language, timeout)
    out_sarif.parent.mkdir(parents=True, exist_ok=True)
    stem = out_sarif.with_suffix("")
    flows = query(
        cpg,
        spec,
        bin_dir,
        timeout,
        max_flows,
        semantics=semantics,
        externals_out=Path(f"{stem}.externals.tsv"),
        sinks_out=Path(f"{stem}.sinks.jsonl"),
    )
    out_sarif.parent.mkdir(parents=True, exist_ok=True)
    out_sarif.write_text(json.dumps(to_sarif(flows, spec), indent=1), encoding="utf-8")
    return len(flows)


def available(bin_dir: Path | None = None) -> bool:
    return all(shutil.which(_bin(bin_dir, n)) for n in ("joern", "joern-parse"))
