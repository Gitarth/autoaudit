"""
Hand-made, language-agnostic features per alert, and leakage-safe groups.

The features mirror what a reviewer checks first: how long and how spread out
the path is, what happens to the value on the way (conversions, hashing,
sanitiser-like calls, collections, string surgery), what guards the sink,
whether other tools agree and whether the AST pruner proves it dead. Call names
on the path are kept as sparse `call=<name>` features; training drops rare ones.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter

from ..alerts import Alert
from ..codeindex import CodeIndex, ancestors, call_name, enclosing_function, node_at_line, walk
from .graph import KINDS, kind_of

PATTERNS = {
    "sanitize": r"saniti[sz]e|escape|encode|clean|strip_?tags|htmlspecial|quote|bleach|purify",
    "validate": r"valid|whitelist|allowlist|matches|isalnum|isdigit|fullmatch|regex|pattern",
    "convert": r"parse(int|long|double|float)|valueof|\bint\(|\bfloat\(|tonumber|number\(|atoi|uuid",
    "hash": r"hash|digest|md5|sha\d|base64|hmac|crypt",
    "collection": r"\.(get|put|add|remove|push|pop|append|insert|set|keys|values)\(|\[[^\]]*\]",
    "string_ops": r"substring|substr|replace|split|trim|slice|concat|join|format|sprintf|\+",
    "constant_assign": r"=\s*(\"[^\"]*\"|'[^']*'|\d+)\s*;?\s*$",
    "prepared": r"prepare|\?\s*[,)]|\$\d|:\w+\b|bind(param|value)?|setstring|parameteri[sz]",
    "reflection": r"invoke|getmethod|forname|reflect|eval\(",
}
_RX = {k: re.compile(v, re.I) for k, v in PATTERNS.items()}
_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_STR = re.compile(r"\"(\\.|[^\"\\])*\"|'(\\.|[^'\\])*'")
_NUM = re.compile(r"\b\d+(\.\d+)?\b")
KEYWORDS = {
    "if", "else", "for", "while", "return", "new", "null", "true", "false", "None", "True", "False",
    "switch", "case", "try", "catch", "throw", "def", "function", "var", "let", "const", "this", "self",
    "int", "long", "String", "string", "boolean", "bool", "void", "public", "private", "static", "final",
}  # fmt: skip


def abstract(code: str) -> str:
    """Code with literals and local names abstracted, keeping called/field names."""
    code = _STR.sub("STR", code)
    code = _NUM.sub("NUM", code)

    def ident(m: re.Match) -> str:
        word, end = m.group(0), m.end()
        rest = code[end : end + 1]
        before = code[m.start() - 1 : m.start()] if m.start() else ""
        if word in KEYWORDS or word in ("STR", "NUM") or rest == "(" or before == ".":
            return word
        return "V"

    return re.sub(r"\s+", " ", _IDENT.sub(ident, code)).strip()


def _flow_lines(alert: Alert, index: CodeIndex) -> list[str]:
    seen, out = set(), []
    for f in alert.flows[:4] or [[]]:
        for s in [*f, None]:
            path, line = (s.path, s.line) if s is not None else (alert.path, alert.line)
            if not line or (path, line) in seen:
                continue
            seen.add((path, line))
            lines = index.lines(path)
            if lines and 0 < line <= len(lines):
                out.append(lines[line - 1].strip())
            elif s is not None and s.code:
                out.append(s.code.strip())
    return out


def slice_group(alert: Alert, index: CodeIndex) -> str:
    """Hash of the abstracted reported path: alerts that differ only in names and
    literals (common in generated test suites and copy-pasted code) share a group."""
    text = "\n".join(abstract(code) for code in _flow_lines(alert, index))
    rule = (alert.cwes or [alert.rule_id])[0]
    return hashlib.sha1(f"{rule}\n{text}".encode()).hexdigest()[:16]


def features(alert: Alert, index: CodeIndex, prune: bool = True) -> dict[str, float]:
    f: dict[str, float] = {}
    flows = alert.flows
    lengths = [len(x) for x in flows] or [0]
    steps = [s for x in flows for s in x]
    f["n_paths"] = len(flows)
    f["path_len_min"] = min(lengths)
    f["path_len_max"] = max(lengths)
    f["n_files"] = len({s.path for s in steps} | {alert.path})
    f["n_functions"] = len({(s.path, s.function) for s in steps if s.function})
    f["has_flow"] = int(bool(flows))
    f["n_tools"] = 1 + len({r.split(":")[0] for r in alert.also_reported_by} - {alert.tool})
    f[f"tool={alert.tool}"] = 1
    for cwe in alert.cwes:
        f[f"cwe={cwe}"] = 1

    lines = _flow_lines(alert, index)
    text = "\n".join(lines)
    for k, rx in _RX.items():
        f[f"path_{k}"] = len(rx.findall(text))
    sink_line = lines[-1] if lines else ""
    f["sink_string_literals"] = len(_STR.findall(sink_line))
    f["sink_concat"] = int("+" in _STR.sub("", sink_line) or "%" in sink_line or "${" in sink_line)
    f["sink_prepared"] = int(bool(_RX["prepared"].search(sink_line)))

    p = index.parsed(alert.path) if alert.line else None
    fn = enclosing_function(p, alert.line) if p is not None else None
    if fn is not None:
        kinds = Counter(KINDS[kind_of(n.type)] for n in walk(fn) if n.is_named)
        f["fn_lines"] = fn.end_point[0] - fn.start_point[0] + 1
        for k in ("if", "switch", "loop", "call", "exception", "return", "assign"):
            f[f"fn_{k}"] = kinds[k]
        node = node_at_line(p, alert.line)
        f["sink_guards"] = sum(1 for a in ancestors(node) if a != fn and KINDS[kind_of(a.type)] == "if")
        names = {call_name(p, n) for n in walk(fn) if n.type in p.spec.calls}
        for name in names - {None}:
            f[f"call={name}"] = 1
    if prune:
        from ..feasibility import infeasible

        try:
            f["ast_dead"] = int(infeasible(alert, index) is not None)
        except Exception:  # pragma: no cover - never fail a dataset over one alert
            f["ast_dead"] = 0
    return f
