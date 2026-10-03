"""
Scanner-neutral alerts.

Every analyzer (Joern, CodeQL, Opengrep, ...) is read through SARIF 2.1.0 into
`Alert`s: a rule, a primary location, and the source-to-sink flow when the
tool reports one.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlparse

_CWE = re.compile(r"cwe[-_/]?0*(\d+)", re.I)


@dataclass
class Step:
    path: str
    line: int | None
    function: str | None = None
    code: str | None = None


@dataclass
class Alert:
    tool: str
    rule_id: str
    message: str
    project: str
    path: str
    line: int | None
    function: str | None = None
    severity: str | None = None
    cwes: list[str] = field(default_factory=list)
    flow: list[Step] = field(default_factory=list)
    alt_flows: list[list[Step]] = field(default_factory=list)  # other paths for the same source -> sink
    label: str | None = None

    @property
    def flows(self) -> list[list[Step]]:
        return [self.flow, *self.alt_flows] if self.flow else list(self.alt_flows)

    @property
    def id(self) -> str:
        """Stable across runs: same tool, rule, sink and source -> same id, whichever
        path the analyzer happens to list first."""
        source = (self.flow[0].path, self.flow[0].line) if self.flow else None
        key = [self.tool, self.rule_id, self.project, self.path, self.line, source]
        return hashlib.sha256(json.dumps(key).encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {"id": self.id, **asdict(self)}

    @classmethod
    def from_dict(cls, d: dict) -> Alert:
        d = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        d["flow"] = [Step(**s) for s in d.get("flow", [])]
        d["alt_flows"] = [[Step(**s) for s in f] for f in d.get("alt_flows", [])]
        return cls(**d)


# ------------------------------------------------------------------------ SARIF
def _uri_to_path(uri: str) -> str:
    if uri.startswith("file:"):
        uri = urlparse(uri).path
    uri = unquote(uri)
    return uri[2:] if uri.startswith("./") else uri


def _location(loc: dict) -> tuple[str, int | None, str | None]:
    phys = loc.get("physicalLocation", {})
    path = _uri_to_path(phys.get("artifactLocation", {}).get("uri", ""))
    line = phys.get("region", {}).get("startLine")
    logical = (loc.get("logicalLocations") or [{}])[0]
    func = logical.get("fullyQualifiedName") or logical.get("name")
    return path, line, func


def _rule_meta(rule: dict) -> tuple[list[str], str | None]:
    props = rule.get("properties", {})
    texts = list(props.get("tags", [])) + [str(props.get("cwe", ""))]
    cwes = sorted({f"CWE-{m}" for t in texts for m in _CWE.findall(t)}, key=lambda c: int(c[4:]))
    sev = props.get("security-severity") or rule.get("defaultConfiguration", {}).get("level")
    return cwes, (str(sev) if sev is not None else None)


def read_sarif(path: Path, project: str | None = None, strip_prefix: str | None = None) -> list[Alert]:
    """Read every result of every run. `strip_prefix` makes absolute paths repo-relative."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    project = project or Path(path).stem
    alerts = []

    def rel(p: str) -> str:
        if strip_prefix and p.startswith(strip_prefix):
            return p[len(strip_prefix) :].lstrip("/")
        return p

    for run in doc.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool = driver.get("name", "unknown")
        rules = driver.get("rules", [])
        by_id = {r.get("id"): r for r in rules}
        for res in run.get("results", []):
            rule = by_id.get(res.get("ruleId"))
            if rule is None and isinstance(res.get("ruleIndex"), int) and res["ruleIndex"] < len(rules):
                rule = rules[res["ruleIndex"]]
            rule = rule or {}
            cwes, sev = _rule_meta(rule)
            p, line, func = _location((res.get("locations") or [{}])[0])
            flows = []
            for cf in res.get("codeFlows", []):
                for tf in cf.get("threadFlows", [])[:1]:
                    steps = []
                    for tfl in tf.get("locations", []):
                        loc = tfl.get("location", {})
                        sp, sl, sf = _location(loc)
                        code = loc.get("message", {}).get("text")
                        steps.append(Step(rel(sp), sl, sf, code))
                    if steps:
                        flows.append(steps)
            alerts.append(
                Alert(
                    tool=tool,
                    rule_id=res.get("ruleId") or rule.get("id", "unknown"),
                    message=res.get("message", {}).get("text", ""),
                    project=project,
                    path=rel(p),
                    line=line,
                    function=func,
                    severity=res.get("level") or sev,
                    cwes=cwes,
                    flow=flows[0] if flows else [],
                    alt_flows=flows[1:],
                )
            )
    return alerts


def write_jsonl(alerts: list[Alert], out: Path) -> None:
    with open(out, "w", encoding="utf-8") as fh:
        for a in alerts:
            fh.write(json.dumps(a.to_dict()) + "\n")


def read_jsonl(path: Path) -> list[Alert]:
    with open(path, encoding="utf-8") as fh:
        return [Alert.from_dict(json.loads(line)) for line in fh if line.strip()]
