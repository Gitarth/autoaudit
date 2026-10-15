"""
Lightweight syntactic taint over tree-sitter ASTs.

Independent of Joern and deliberately over-approximate (no control flow, no
types): a variable is tainted if it is assigned from an expression that
mentions a source call, a tainted variable, or a call to a function that
returns tainted data; taint also enters a receiver through `obj.m(tainted)`,
a loop variable through `for (x : tainted)`, and a parameter when any caller
passes tainted data in that position. A rule's sanitizers stop taint.

Every tainting assignment is remembered, so for a sink the module can rebuild
the chains of lines from the source to the sink. Those chains are ordinary
flows: the AST feasibility checks (dead branches, constant collection reads)
apply to them exactly as to Joern's flows.

Used by the sink sweep to recover flows the dataflow engine loses
(e.g. `param.split(" ")[0]`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .codeindex import CodeIndex, Parsed, call_name, walk
from .feasibility import ASSIGNMENTS, DECLARATORS

FOR_EACH = {
    "enhanced_for_statement": ("name", "value"),
    "for_statement": ("left", "right"),
    "for_in_statement": ("left", "right"),
}
PARAMS = {
    "formal_parameter",
    "spread_parameter",
    "typed_parameter",
    "default_parameter",
    "typed_default_parameter",
    "required_parameter",
    "optional_parameter",
}
MAX_PATHS = 8
MAX_DEPTH = 25


def _compile(items) -> list[re.Pattern]:
    out = []
    for item in items:
        try:
            out.append(re.compile(item["pattern"]))
        except re.error:
            pass
    return out


def _params(p: Parsed, fn) -> list[tuple[str, object]]:
    """(name, node) of each formal parameter, in order."""
    plist = fn.child_by_field_name("parameters")
    out = []
    if plist is None:
        return out
    for c in plist.named_children:
        if c.type == "identifier":
            out.append((p.text(c), c))
        elif c.type in PARAMS or c.type == "assignment_pattern":
            name = (
                c.child_by_field_name("name")
                or c.child_by_field_name("pattern")
                or c.child_by_field_name("left")
            )
            if name is None:
                name = next((x for x in c.named_children if x.type == "identifier"), None)
            if name is not None:
                out.append((p.text(name), c))
    return out


@dataclass(frozen=True)
class _Def:
    line: int
    reads: frozenset  # tainted identifiers the defining expression reads
    source: bool  # the expression itself contains a source (or a tainted parameter)


@dataclass
class _FnTaint:
    tainted: set = field(default_factory=set)
    defs: dict = field(default_factory=dict)  # identifier -> list[_Def]


class LightTaint:
    def __init__(self, index: CodeIndex, spec: dict, rule_id: str | None = None, rounds: int = 4):
        """With `rule_id`, that rule's sanitizers stop taint (their results are clean)."""
        self.index = index
        calls, annotations = [], []
        for r in spec["rules"]:
            for s in r["sources"]:
                (annotations if s.get("kind") == "annotated_param" else calls).append(s)
        self.sources = _compile(calls)
        self.annotations = _compile(annotations)
        self.sanitizers = _compile(
            s for r in spec["rules"] if r["id"] == rule_id for s in r.get("sanitizers", [])
        )
        self.rounds = rounds
        # Function summaries are keyed (file, name) when the file defines that name, else
        # ("*", name): a call resolves to a same-file definition before any other.
        self.tainted_params: dict[tuple[str, str], set[int]] = {}
        self.tainted_returns: set[tuple[str, str]] = set()
        self._local: dict[str, set[str]] = {}
        self._rel = ""
        self._fn: dict[tuple[str, int], _FnTaint] = {}
        self._done = False

    # ------------------------------------------------------------- predicates
    def _call(self, p: Parsed, n, patterns) -> bool:
        if n.type not in p.spec.calls or not patterns:
            return False
        name = call_name(p, n) or ""
        return any(rx.fullmatch(name) for rx in patterns)

    def _key(self, rel: str, name: str) -> tuple[str, str]:
        return (rel, name) if name in self._local.get(rel, ()) else ("*", name)

    def _is_source(self, p: Parsed, n) -> bool:
        return self._call(p, n, self.sources) or (
            n.type in p.spec.calls and self._key(self._rel, call_name(p, n) or "") in self.tainted_returns
        )

    def _scan(self, p: Parsed, node, tainted: set[str]) -> tuple[set[str], bool]:
        """(tainted identifiers read, contains a source) for an expression; sanitizer
        subtrees are skipped because their result is clean."""
        reads, source = set(), False
        stack = [node]
        while stack:
            x = stack.pop()
            if self._call(p, x, self.sanitizers):
                continue
            if x.type == "identifier" and p.text(x) in tainted:
                reads.add(p.text(x))
            elif self._is_source(p, x):
                source = True
            stack.extend(x.children)
        return reads, source

    # ---------------------------------------------------------------- analysis
    def _function(self, p: Parsed, fn, name: str) -> _FnTaint:
        ft = _FnTaint()

        def add(target: str, line: int, reads: set[str], source: bool) -> bool:
            defs = ft.defs.setdefault(target, [])
            d = _Def(line, frozenset(reads), source)
            if d in defs:
                return False
            defs.append(d)
            ft.tainted.add(target)
            return True

        positions = self.tainted_params.get((self._rel, name), set()) | self.tainted_params.get(
            ("*", name), set()
        )
        for i, (pname, pnode) in enumerate(_params(p, fn)):
            text = p.text(pnode)
            if i in positions or ("@" in text and any(rx.search(text) for rx in self.annotations)):
                add(pname, pnode.start_point[0] + 1, set(), True)

        nodes = list(walk(fn))
        for _ in range(6):
            changed = False
            for n in nodes:
                line = n.start_point[0] + 1
                if n.type in DECLARATORS or n.type in ASSIGNMENTS:
                    left = n.child_by_field_name("name") or n.child_by_field_name("left")
                    right = n.child_by_field_name("value") or n.child_by_field_name("right")
                    if left is None or right is None:
                        continue
                    reads, source = self._scan(p, right, ft.tainted)
                    if reads or source:
                        for x in walk(left):
                            if x.type == "identifier":
                                changed |= add(p.text(x), line, reads, source)
                elif n.type in FOR_EACH:
                    var_f, coll_f = FOR_EACH[n.type]
                    var, coll = n.child_by_field_name(var_f), n.child_by_field_name(coll_f)
                    if var is None or coll is None:
                        continue
                    reads, source = self._scan(p, coll, ft.tainted)
                    if reads or source:
                        for x in walk(var):
                            if x.type == "identifier":
                                changed |= add(p.text(x), line, reads, source)
                elif n.type in p.spec.calls and not self._call(p, n, self.sanitizers):
                    args = n.child_by_field_name("arguments")
                    recv = n.child_by_field_name("object")
                    if recv is None:
                        f = n.child_by_field_name("function")
                        recv = f.child_by_field_name("object") if f is not None else None
                    if recv is not None and recv.type == "identifier" and args is not None:
                        reads, source = self._scan(p, args, ft.tainted)
                        if reads or source:  # sb.append(x), list.add(x), map.put(k, x)
                            changed |= add(p.text(recv), line, reads, source)
            if not changed:
                break
        return ft

    def _analyze(self) -> None:
        """Whole-repository fixpoint over parameter and return taint."""
        files = self.index.files()
        for rel in files:
            p = self.index.parsed(rel)
            if p is not None:
                self._local[rel] = {
                    p.text(n.child_by_field_name("name"))
                    for n in walk(p.root)
                    if n.type in p.spec.functions and n.child_by_field_name("name") is not None
                }
        for _ in range(self.rounds):
            changed = False
            for rel in files:
                p = self.index.parsed(rel)
                if p is None:
                    continue
                self._rel = rel
                for fn in (n for n in walk(p.root) if n.type in p.spec.functions):
                    name_node = fn.child_by_field_name("name")
                    name = p.text(name_node) if name_node is not None else "<anonymous>"
                    ft = self._function(p, fn, name)
                    self._fn[(rel, fn.start_byte)] = ft
                    for n in walk(fn):
                        if n.type == "return_statement" and (rel, name) not in self.tainted_returns:
                            reads, source = self._scan(p, n, ft.tainted)
                            if reads or source:
                                self.tainted_returns.update({(rel, name), ("*", name)})
                                changed = True
                        if n.type in p.spec.calls:
                            callee = call_name(p, n)
                            args = n.child_by_field_name("arguments")
                            if not callee or args is None:
                                continue
                            for i, a in enumerate(x for x in args.named_children if x.type != "comment"):
                                reads, source = self._scan(p, a, ft.tainted)
                                key = self._key(rel, callee)
                                if (reads or source) and i not in self.tainted_params.get(key, set()):
                                    self.tainted_params.setdefault(key, set()).add(i)
                                    changed = True
            if not changed:
                break
        self._done = True

    # ------------------------------------------------------------------ query
    def _chains(self, ft: _FnTaint, name: str, depth: int, seen: frozenset) -> list[list[int]]:
        """Line chains from where `name` became tainted to its tainting definition(s)."""
        if depth > MAX_DEPTH:
            return [[]]
        out = []
        for d in sorted(ft.defs.get(name, []), key=lambda d: d.line):
            preds = [r for r in d.reads if r not in seen and r != name]
            if d.source or not preds:
                out.append([d.line])
            for r in preds:
                for chain in self._chains(ft, r, depth + 1, seen | {name}):
                    out.append(chain + [d.line])
                    if len(out) >= MAX_PATHS:
                        return out
            if len(out) >= MAX_PATHS:
                break
        return out or [[]]

    def sink_flows(self, rel: str, line: int) -> tuple[list[str], list[list[int]]] | None:
        """(tainted things used in the arguments of the call(s) on `line`, line chains from
        source to sink), or None if nothing there can derive from user input."""
        if not self._done:
            self._analyze()
        p = self.index.parsed(rel)
        if p is None:
            return None
        self._rel = rel
        hits: set[str] = set()
        chains: list[list[int]] = []
        for fn in (
            n
            for n in walk(p.root)
            if n.type in p.spec.functions and n.start_point[0] < line <= n.end_point[0] + 1
        ):
            ft = self._fn.get((rel, fn.start_byte), _FnTaint())
            for n in walk(fn):
                if n.type not in p.spec.calls or n.start_point[0] + 1 != line:
                    continue
                args = n.child_by_field_name("arguments")
                if args is None:
                    continue
                reads, source = self._scan(p, args, ft.tainted)
                if source:
                    hits.add("<source call>")
                    chains.append([line])
                for r in sorted(reads):
                    hits.add(r)
                    chains += [c + [line] for c in self._chains(ft, r, 0, frozenset())]
        if not hits:
            return None
        unique = []
        for c in chains:
            c = [ln for i, ln in enumerate(c) if i == 0 or ln != c[i - 1]]
            if c not in unique:
                unique.append(c)
        return sorted(hits), unique[:MAX_PATHS]

    def call_is_tainted(self, rel: str, line: int, code: str = "") -> list[str] | None:
        found = self.sink_flows(rel, line)
        return found[0] if found else None
