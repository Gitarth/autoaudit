"""
Read a Fortify FPR (a zip containing audit.fvdl, audit.xml and src-archive/)
and turn its audited findings into labeled samples.

The FPR is opened once and read directly from the zip; nothing is extracted
to disk.
"""

from __future__ import annotations

import hashlib
import logging
import posixpath
import zipfile
from collections import Counter
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path

from lxml import etree

log = logging.getLogger(__name__)

# GUID of Fortify's built-in "Analysis" tag. Audit verdicts live under it.
ANALYSIS_TAG_ID = "87f2364f-dcd4-49e6-861d-f8d3f351686b"
ANALYSIS_VALUES = frozenset(
    {"Not an Issue", "Suspicious", "Exploitable", "Reliability Issue", "Bad Practice"}
)

# Hardened parser: FPRs are build artifacts, but never resolve entities.
_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=True)


@dataclass
class Finding:
    project: str
    instance_id: str
    kingdom: str | None
    type: str
    subtype: str | None
    severity: float | None
    confidence: float | None
    path: str  # primary (sink) location as reported by Fortify
    line: int | None
    function: str | None  # enclosing function, when the FVDL records it
    function_line: int | None
    analysis: str | None = None
    source_sha: str | None = None

    @property
    def category(self) -> str:
        return f"{self.type}: {self.subtype}" if self.subtype else self.type

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category
        return d


@dataclass
class FPR:
    """Parsed view of one FPR file."""

    path: Path
    project: str
    findings: list[Finding] = field(default_factory=list)
    _zip: zipfile.ZipFile | None = None
    _index: dict[str, str] = field(default_factory=dict)
    _source_base: str | None = None

    @classmethod
    def open(cls, path: str | Path, analysis_tag_id: str = ANALYSIS_TAG_ID) -> FPR:
        path = Path(path)
        fpr = cls(path=path, project=path.stem)
        fpr._zip = zipfile.ZipFile(path)
        names = set(fpr._zip.namelist())
        fvdl = _parse(fpr._zip, "audit.fvdl")
        audit = _parse(fpr._zip, "audit.xml") if "audit.xml" in names else None
        if "src-archive/index.xml" in names:
            fpr._index = _parse_index(_parse(fpr._zip, "src-archive/index.xml"))
        fpr._source_base = _text(fvdl.find(".//{*}Build/{*}SourceBasePath"))

        verdicts = _parse_verdicts(audit, analysis_tag_id) if audit is not None else {}
        fpr.findings = list(_parse_findings(fvdl, fpr.project))
        for f in fpr.findings:
            f.analysis = verdicts.get(f.instance_id)
        return fpr

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()
            self._zip = None

    def __enter__(self) -> FPR:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------ queries
    def analyzed(self, labels: set[str] | None = None) -> list[Finding]:
        """Findings that carry an audit verdict (optionally restricted to `labels`)."""
        return [
            f for f in self.findings if f.analysis is not None and (labels is None or f.analysis in labels)
        ]

    def stats(self) -> dict:
        by_label = Counter(f.analysis or "Unaudited" for f in self.findings)
        return {"project": self.project, "total": len(self.findings), **by_label}

    # ------------------------------------------------------------------ sources
    def archive_entry(self, path: str) -> str | None:
        """Map a path from the FVDL to its entry inside src-archive/."""
        if path in self._index:
            return self._index[path]
        if self._source_base:
            joined = posixpath.join(self._source_base.replace("\\", "/"), path)
            if joined in self._index:
                return self._index[joined]
        # Last resort: a unique key that ends with the relative path.
        suffix = "/" + path.lstrip("/")
        hits = [v for k, v in self._index.items() if k.replace("\\", "/").endswith(suffix)]
        return hits[0] if len(hits) == 1 else None

    def read_source(self, path: str) -> bytes | None:
        entry = self.archive_entry(path)
        if entry is None or self._zip is None:
            return None
        try:
            return self._zip.read(entry)
        except KeyError:
            return None


# ---------------------------------------------------------------------- helpers
def _parse(zf: zipfile.ZipFile, name: str) -> etree._ElementTree:
    with zf.open(name) as fh:
        return etree.parse(fh, _PARSER)


def _text(el) -> str | None:
    return el.text.strip() if el is not None and el.text else None


def _float(el) -> float | None:
    t = _text(el)
    return float(t) if t else None


def _int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_index(tree) -> dict[str, str]:
    return {e.get("key"): (e.text or "").strip() for e in tree.iter("{*}entry") if e.get("key")}


def _parse_verdicts(audit, analysis_tag_id: str) -> dict[str, str]:
    """instanceId -> Analysis value, read from the Analysis tag by its ID.

    If an issue has no tag with that ID (custom audit templates), fall back to
    the single tag whose value is a known analysis verdict.
    """
    verdicts: dict[str, str] = {}
    for issue in audit.iter("{*}Issue"):
        iid = issue.get("instanceId")
        if not iid:
            continue
        values = {}
        for tag in issue.iterchildren("{*}Tag"):
            values[tag.get("id")] = _text(tag.find("{*}Value"))
        verdict = values.get(analysis_tag_id)
        if verdict is None:
            candidates = {v for v in values.values() if v in ANALYSIS_VALUES}
            if len(candidates) == 1:
                verdict = candidates.pop()
        if verdict is not None:
            verdicts[iid] = verdict
    return verdicts


def _primary_location(vuln, node_pool: dict[str, etree._Element]):
    """Return the SourceLocation Fortify reports for the issue.

    Prefers the trace node flagged isDefault="true" (the sink), following
    NodeRef indirections into UnifiedNodePool. Falls back to the last node of
    the first trace, which for dataflow findings is also the sink.
    """
    last = None
    for trace in vuln.iterfind(".//{*}Trace"):
        for entry in trace.iterfind(".//{*}Entry"):
            node = entry.find("{*}Node")
            if node is None:
                ref = entry.find("{*}NodeRef")
                node = node_pool.get(ref.get("id")) if ref is not None else None
            if node is None:
                continue
            loc = node.find("{*}SourceLocation")
            if loc is None:
                continue
            if node.get("isDefault") == "true":
                return loc
            last = loc
        if last is not None:
            return last
    return vuln.find(".//{*}SourceLocation")


def _parse_findings(fvdl, project: str) -> Iterator[Finding]:
    pool = {n.get("id"): n for n in fvdl.iterfind(".//{*}UnifiedNodePool/{*}Node")}
    for vuln in fvdl.iter("{*}Vulnerability"):
        iid = _text(vuln.find(".//{*}InstanceID"))
        if iid is None:
            continue
        loc = _primary_location(vuln, pool)
        func = vuln.find(".//{*}Context/{*}Function")
        func_loc = vuln.find(".//{*}Context/{*}FunctionDeclarationSourceLocation")
        yield Finding(
            project=project,
            instance_id=iid,
            kingdom=_text(vuln.find(".//{*}ClassInfo/{*}Kingdom")),
            type=_text(vuln.find(".//{*}ClassInfo/{*}Type")) or "Unknown",
            subtype=_text(vuln.find(".//{*}ClassInfo/{*}Subtype")),
            severity=_float(vuln.find(".//{*}InstanceSeverity")),
            confidence=_float(vuln.find(".//{*}Confidence")),
            path=loc.get("path") if loc is not None else "",
            line=_int(loc.get("line")) if loc is not None else None,
            function=func.get("name") if func is not None else None,
            function_line=_int(func_loc.get("line")) if func_loc is not None else None,
        )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
