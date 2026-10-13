"""
Per-alert code graphs (Devign-style) from tree-sitter ASTs.

Nodes are the named AST nodes of the functions on the alert's reported paths,
the sink's function first. Each node carries:

  [type id, token id, kind, on_flow, is_sink, is_source, in_sink_function]

`type id` and `token id` are stable hashes into a fixed vocabulary (no
vocabulary file to ship); `kind` is a coarse category shared by all grammars
(call, identifier, string, if, loop, ...). Tokens are abstracted: variable
names become VAR, literals STR/NUM; call, field and type names are kept since
they name the APIs that decide most verdicts.

Edges ([src, dst, type]):
  AST   parent -> child
  NEXT  named sibling -> next named sibling (statement order)
  TOKEN leaf -> next leaf (source order)
  USE   previous occurrence of a variable -> next occurrence (def-use, approximate)
  FLOW  statement of one reported step -> statement of the next step
  CALL  call -> the included function it resolves to by name
"""

from __future__ import annotations

import zlib

from ..alerts import Alert
from ..codeindex import CodeIndex, Parsed, call_name, enclosing_function, node_at_line, walk

VOCAB = 1 << 14
EDGE_TYPES = ("AST", "NEXT", "TOKEN", "USE", "FLOW", "CALL")
AST, NEXT, TOKEN, USE, FLOW, CALL = range(len(EDGE_TYPES))
N_FLAGS = 4

KINDS = (
    "other",
    "call",
    "identifier",
    "string",
    "number",
    "constant",
    "if",
    "loop",
    "switch",
    "assign",
    "declaration",
    "return",
    "binary",
    "member",
    "parameter",
    "exception",
    "function",
    "arguments",
    "index",
    "type",
    "block",
)
# matched against the "_"-separated parts of a node type, first rule wins
_KIND_RULES = [
    ("call", {"call", "invocation", "creation"}, {"new_expression"}),
    ("string", {"string", "char", "character", "template", "heredoc"}, set()),
    ("number", {"integer", "float", "decimal", "number", "hex", "octal", "real"}, set()),
    ("constant", {"true", "false", "null", "nil", "none", "boolean", "undefined"}, set()),
    ("type", {"type"}, set()),
    ("function", {"lambda", "arrow", "function", "method", "constructor", "closure"}, set()),
    ("parameter", {"parameter", "parameters"}, set()),
    ("if", {"if", "elif", "else", "conditional", "ternary"}, set()),
    ("loop", {"for", "foreach", "while", "do", "loop"}, set()),
    ("switch", {"switch", "case", "match"}, set()),
    ("assign", {"assignment", "augmented"}, set()),
    ("declaration", {"declaration", "declarator"}, set()),
    ("return", {"return", "yield"}, set()),
    ("binary", {"binary", "comparison", "unary", "update"}, {"boolean_operator", "not_operator"}),
    ("member", {"field", "member", "attribute", "selector", "scoped"}, set()),
    ("exception", {"try", "catch", "throw", "finally", "except", "raise"}, set()),
    ("arguments", {"argument", "arguments"}, set()),
    ("index", {"subscript", "index", "slice"}, {"array_access", "element_access_expression"}),
    ("identifier", {"identifier", "name"}, set()),
    ("block", {"block", "body", "list"}, set()),
]
KIND_ID = {k: i for i, k in enumerate(KINDS)}


def stable_hash(text: str, size: int = VOCAB) -> int:
    return zlib.crc32(text.encode("utf-8")) % size


_kind_cache: dict[str, int] = {}


def kind_of(node_type: str) -> int:
    k = _kind_cache.get(node_type)
    if k is None:
        parts = set(node_type.split("_"))
        k = next((KIND_ID[n] for n, _, exact in _KIND_RULES if node_type in exact), None)
        if k is None:
            k = next((KIND_ID[n] for n, words, _ in _KIND_RULES if parts & words), 0)
        _kind_cache[node_type] = k
    return k


def _named(node):
    return [c for c in node.children if c.is_named]


def token(p: Parsed, node) -> str:
    """Abstracted lexical token of a node ('' for inner nodes without one)."""
    kind = KINDS[kind_of(node.type)]
    if kind == "string":
        return "STR"
    if kind == "number":
        return "NUM"
    if kind == "constant":
        return p.text(node).lower()[:8]
    if kind == "binary":
        ops = [c.type for c in node.children if not c.is_named]
        return "op:" + "".join(ops[:2])
    if kind == "type" and not _named(node):
        return "type:" + p.text(node)
    if kind != "identifier" or _named(node):
        return ""
    parent = node.parent
    if parent is not None and parent.type in p.spec.calls and call_name(p, parent) == p.text(node):
        # the callee name, not an argument that happens to be spelled the same
        for field in ("name", "function", "type", "constructor"):
            f = parent.child_by_field_name(field)
            if f is not None and (f == node or f.end_byte == node.end_byte):
                return "call:" + p.text(node)
    if parent is not None and KINDS[kind_of(parent.type)] == "member":
        last = _named(parent)[-1] if _named(parent) else None
        if last == node:
            return "field:" + p.text(node)
    if parent is not None and parent.type in p.spec.functions:
        return "FUNC"
    return "VAR"


def _variable(p: Parsed, node) -> str | None:
    if node.type == "identifier" and not _named(node):
        parent = node.parent
        if parent is not None and parent.type in p.spec.calls and call_name(p, parent) == p.text(node):
            return None
        if parent is not None and KINDS[kind_of(parent.type)] == "member" and _named(parent)[0] != node:
            return None
        return p.text(node)
    return None


def _key(node) -> tuple:
    return (node.start_byte, node.end_byte, node.type)


class _Builder:
    def __init__(self, max_nodes: int):
        self.max_nodes = max_nodes
        self.x: list[list[int]] = []
        self.edges: list[list[int]] = []
        self.line_nodes: dict[tuple[str, int], int] = {}  # first (outermost) node starting on a line
        self.functions: dict[str, int] = {}  # function name -> root node id
        self.calls: list[tuple[int, str | None]] = []

    def add_function(self, p: Parsed, rel: str, fn, marks: dict, in_sink_fn: bool) -> bool:
        if len(self.x) >= self.max_nodes:
            return False
        ids: dict[tuple, int] = {}  # (start, end, type) -> node id
        stack = [(fn, None)]
        last_leaf = None
        last_use: dict[str, int] = {}
        while stack and len(self.x) < self.max_nodes:
            node, parent_id = stack.pop()
            line = node.start_point[0] + 1
            flags = marks.get(line, (0, 0, 0))
            nid = len(self.x)
            self.x.append(
                [
                    stable_hash("t:" + node.type),
                    stable_hash(token(p, node)),
                    kind_of(node.type),
                    *flags,
                    int(in_sink_fn),
                ]
            )
            ids[_key(node)] = nid
            self.line_nodes.setdefault((rel, line), nid)
            if parent_id is not None:
                self.edges.append([parent_id, nid, AST])
            children = _named(node)
            if not children:
                if last_leaf is not None:
                    self.edges.append([last_leaf, nid, TOKEN])
                last_leaf = nid
                var = _variable(p, node)
                if var is not None:
                    if var in last_use:
                        self.edges.append([last_use[var], nid, USE])
                    last_use[var] = nid
            for c in reversed(children):
                stack.append((c, nid))
        # statement order: consecutive named siblings that were both kept
        for n in walk(fn):
            kids = [k for k in (ids.get(_key(c)) for c in _named(n)) if k is not None]
            self.edges.extend([a, b, NEXT] for a, b in zip(kids, kids[1:]))
            if n.type in p.spec.calls and _key(n) in ids:
                self.calls.append((ids[_key(n)], call_name(p, n)))
        root, name = ids.get(_key(fn)), fn.child_by_field_name("name")
        if root is not None and name is not None:
            self.functions.setdefault(p.text(name), root)
        return True

    def finish(self, flow_lines: list[tuple[str, int]]) -> dict:
        for nid, name in self.calls:
            target = self.functions.get(name or "")
            if target is not None:
                self.edges.append([nid, target, CALL])
        prev = None
        for key in flow_lines:
            cur = self.line_nodes.get(key)
            if cur is not None and prev is not None and cur != prev:
                self.edges.append([prev, cur, FLOW])
            if cur is not None:
                prev = cur
        return {"x": self.x, "e": self.edges}


def build_graph(alert: Alert, index: CodeIndex, max_nodes: int = 1500, max_functions: int = 8) -> dict | None:
    """Code graph for one alert, or None if the sink's file cannot be parsed."""
    flows = alert.flows[:4] or [[]]
    sources = {(f[0].path, f[0].line) for f in flows if f}
    on_flow = {(s.path, s.line) for f in flows for s in f if s.line}
    sink = (alert.path, alert.line)
    on_flow.add(sink)

    # functions: the sink's first, then walking back along the first path
    order: list[tuple[str, int]] = [sink]
    for f in flows:
        order += [(s.path, s.line) for s in reversed(f) if s.line]
    seen: set = set()
    funcs = []
    for rel, line in order:
        p = index.parsed(rel)
        if p is None or not line:
            continue
        fn = enclosing_function(p, line)
        if fn is None:
            fn = node_at_line(p, line)
            if fn is None:
                continue
        key = (rel, fn.start_byte, fn.end_byte)
        if key in seen:
            continue
        seen.add(key)
        funcs.append((rel, p, fn))
        if len(funcs) >= max_functions:
            break
    if not funcs or funcs[0][0] != alert.path:
        return None

    b = _Builder(max_nodes)
    for i, (rel, p, fn) in enumerate(funcs):
        marks = {
            line: (1, int((rel, line) == sink), int((rel, line) in sources))
            for (r, line) in on_flow
            if r == rel
        }
        if not b.add_function(p, rel, fn, marks, in_sink_fn=i == 0):
            break
    flow_lines = [(s.path, s.line) for s in flows[0] if s.line] + [sink] if flows[0] else [sink]
    return b.finish(flow_lines)
