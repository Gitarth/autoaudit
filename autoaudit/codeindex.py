"""
Language-agnostic code navigation over tree-sitter ASTs: what a human triager
does in an IDE (open the enclosing function, go to definition, find callers,
ignore comments), as plain functions an LLM can call as tools.

Grammars come from the per-language wheels (tree-sitter-java, -python, ...),
which bundle the compiled grammar: no runtime downloads. Install them with
`pip install autoaudit[ast]`.
"""

from __future__ import annotations

import importlib
import logging
import re
import threading
from dataclasses import dataclass
from functools import cache
from pathlib import Path

log = logging.getLogger(__name__)

try:
    import tree_sitter as ts
except ImportError:  # pragma: no cover - exercised only without the extra
    ts = None


@dataclass(frozen=True)
class LangSpec:
    name: str
    module: str
    factory: str
    functions: tuple[str, ...]
    classes: tuple[str, ...]
    calls: tuple[str, ...]
    comments: tuple[str, ...] = ("comment", "line_comment", "block_comment")


LANGS = {
    "java": LangSpec(
        "java",
        "tree_sitter_java",
        "language",
        ("method_declaration", "constructor_declaration"),
        ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration"),
        ("method_invocation", "object_creation_expression"),
    ),
    "python": LangSpec(
        "python", "tree_sitter_python", "language", ("function_definition",), ("class_definition",), ("call",)
    ),
    "javascript": LangSpec(
        "javascript",
        "tree_sitter_javascript",
        "language",
        (
            "function_declaration",
            "method_definition",
            "function_expression",
            "arrow_function",
            "generator_function_declaration",
        ),
        ("class_declaration",),
        ("call_expression", "new_expression"),
    ),
    "typescript": LangSpec(
        "typescript",
        "tree_sitter_typescript",
        "language_typescript",
        ("function_declaration", "method_definition", "function_expression", "arrow_function"),
        ("class_declaration", "interface_declaration"),
        ("call_expression", "new_expression"),
    ),
    "tsx": LangSpec(
        "tsx",
        "tree_sitter_typescript",
        "language_tsx",
        ("function_declaration", "method_definition", "function_expression", "arrow_function"),
        ("class_declaration", "interface_declaration"),
        ("call_expression", "new_expression"),
    ),
    "go": LangSpec(
        "go",
        "tree_sitter_go",
        "language",
        ("function_declaration", "method_declaration"),
        ("type_declaration",),
        ("call_expression",),
    ),
    "php": LangSpec(
        "php",
        "tree_sitter_php",
        "language_php",
        ("function_definition", "method_declaration"),
        ("class_declaration",),
        (
            "function_call_expression",
            "member_call_expression",
            "scoped_call_expression",
            "object_creation_expression",
        ),
    ),
    "csharp": LangSpec(
        "csharp",
        "tree_sitter_c_sharp",
        "language",
        ("method_declaration", "constructor_declaration", "local_function_statement"),
        ("class_declaration", "interface_declaration", "struct_declaration", "record_declaration"),
        ("invocation_expression", "object_creation_expression"),
    ),
}
EXT = {
    ".java": "java",
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".go": "go",
    ".php": "php",
    ".cs": "csharp",
}
SKIP_DIRS = {".git", "node_modules", "vendor", "target", "build", "dist", ".venv", "venv", "__pycache__"}


def available() -> bool:
    return ts is not None


@cache
def parser_for(lang: str):
    if ts is None:
        raise RuntimeError("tree-sitter is not installed: pip install 'autoaudit[ast]'")
    spec = LANGS[lang]
    try:
        mod = importlib.import_module(spec.module)
    except ImportError as err:
        raise RuntimeError(
            f"grammar for {lang} missing: pip install {spec.module.replace('_', '-')}"
        ) from err
    return ts.Parser(ts.Language(getattr(mod, spec.factory)()))


def lang_of(path: str | Path) -> str | None:
    return EXT.get(Path(path).suffix.lower())


# ------------------------------------------------------------------ parsing
@dataclass
class Parsed:
    lang: str
    source: bytes
    tree: object

    @property
    def root(self):
        return self.tree.root_node

    def text(self, node) -> str:
        return self.source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    @property
    def spec(self) -> LangSpec:
        return LANGS[self.lang]


def parse_bytes(source: bytes, lang: str) -> Parsed:
    return Parsed(lang, source, parser_for(lang).parse(source))


def walk(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def node_at_line(p: Parsed, line: int):
    """Smallest named node covering the first non-blank character of a 1-based line."""
    lines = p.source.split(b"\n")
    if not 1 <= line <= len(lines):
        return None
    raw = lines[line - 1]
    col = len(raw) - len(raw.lstrip())
    n = p.root.named_descendant_for_point_range((line - 1, col), (line - 1, max(col, len(raw) - 1)))
    return n


def ancestors(node):
    while node is not None:
        yield node
        node = node.parent


def enclosing_function(p: Parsed, line: int):
    n = node_at_line(p, line)
    for a in ancestors(n):
        if a.type in p.spec.functions:
            return a
    return None


def function_name(p: Parsed, fn) -> str:
    name = fn.child_by_field_name("name")
    if name is None and fn.parent is not None and fn.parent.type == "variable_declarator":
        name = fn.parent.child_by_field_name("name")  # const f = () => ...
    return p.text(name) if name is not None else "<anonymous>"


def strip_comments(source: bytes, lang: str) -> bytes:
    """Blank out comments, keeping every byte offset and line number intact."""
    p = parse_bytes(source, lang)
    out = bytearray(source)
    for n in walk(p.root):
        if n.type in p.spec.comments:
            for i in range(n.start_byte, n.end_byte):
                if out[i] not in (10, 13):
                    out[i] = 32
    return bytes(out)


def call_name(p: Parsed, call) -> str | None:
    """Short callee name of a call node, e.g. `executeQuery` for st.executeQuery(x)."""
    for field in ("name", "function", "type", "constructor"):
        f = call.child_by_field_name(field)
        if f is None:
            continue
        text = p.text(f)
        return re.split(r"[.:>\\]+", text)[-1].split("(")[0].split("<")[0].strip() or None
    return None


# -------------------------------------------------------------------- index
@dataclass
class Symbol:
    name: str
    kind: str  # function | class
    path: str
    line: int
    end_line: int
    signature: str


@dataclass
class CallSite:
    callee: str
    path: str
    line: int
    caller: str
    code: str


class CodeIndex:
    """Lazy, whole-repository symbol index (definitions and call sites)."""

    def __init__(self, root: Path, strip: bool = True, max_files: int = 20_000):
        self.root = Path(root)
        self.strip = strip
        self.max_files = max_files
        self._parsed: dict[str, Parsed | None] = {}
        self._symbols: list[Symbol] | None = None
        self._calls: list[CallSite] | None = None
        self._lock = threading.RLock()  # shared by triage worker threads

    # files ---------------------------------------------------------------
    def files(self) -> list[str]:
        out = []
        for p in sorted(self.root.rglob("*")):
            if len(out) >= self.max_files:
                break
            if (
                p.is_file()
                and lang_of(p)
                and not any(part in SKIP_DIRS for part in p.relative_to(self.root).parts[:-1])
            ):
                out.append(p.relative_to(self.root).as_posix())
        return out

    def resolve(self, rel: str) -> Path | None:
        p = (self.root / rel).resolve()
        try:
            p.relative_to(self.root.resolve())
        except ValueError:
            return None
        return p if p.is_file() else None

    def parsed(self, rel: str) -> Parsed | None:
        with self._lock:
            return self._parsed_locked(rel)

    def _parsed_locked(self, rel: str) -> Parsed | None:
        if rel not in self._parsed:
            p, lang = self.resolve(rel), lang_of(rel)
            if p is None or lang is None:
                self._parsed[rel] = None
            else:
                src = p.read_bytes()
                if self.strip:
                    src = strip_comments(src, lang)
                self._parsed[rel] = parse_bytes(src, lang)
        return self._parsed[rel]

    def lines(self, rel: str) -> list[str] | None:
        p = self.parsed(rel)
        if p is not None:
            return p.source.decode("utf-8", errors="replace").split("\n")
        path = self.resolve(rel)
        return path.read_text(encoding="utf-8", errors="replace").split("\n") if path else None

    # navigation ----------------------------------------------------------
    def function_span(self, rel: str, line: int) -> tuple[int, int, str] | None:
        p = self.parsed(rel)
        fn = enclosing_function(p, line) if p else None
        if fn is None:
            return None
        return fn.start_point[0] + 1, fn.end_point[0] + 1, function_name(p, fn)

    def _build(self) -> None:
        symbols, calls = [], []
        for rel in self.files():
            p = self.parsed(rel)
            if p is None:
                continue
            lines = p.source.decode("utf-8", errors="replace").split("\n")
            for n in walk(p.root):
                if n.type in p.spec.functions or n.type in p.spec.classes:
                    kind = "function" if n.type in p.spec.functions else "class"
                    first = n.start_point[0]
                    symbols.append(
                        Symbol(
                            function_name(p, n),
                            kind,
                            rel,
                            first + 1,
                            n.end_point[0] + 1,
                            lines[first].strip()[:200],
                        )
                    )
                elif n.type in p.spec.calls:
                    callee = call_name(p, n)
                    if callee:
                        fn = next((a for a in ancestors(n.parent) if a.type in p.spec.functions), None)
                        line = n.start_point[0]
                        calls.append(
                            CallSite(
                                callee,
                                rel,
                                line + 1,
                                function_name(p, fn) if fn else "<top level>",
                                lines[line].strip()[:200],
                            )
                        )
        self._symbols, self._calls = symbols, calls

    def _ensure_index(self) -> None:
        with self._lock:
            if self._symbols is None:
                self._build()

    def definitions(self, name: str) -> list[Symbol]:
        self._ensure_index()
        return [s for s in self._symbols if s.name == name]

    def callers(self, name: str) -> list[CallSite]:
        self._ensure_index()
        return [c for c in self._calls if c.callee == name]

    def callers_in(self, rel: str) -> list[CallSite]:
        """Every call site in one file (parses just that file)."""
        p = self.parsed(rel)
        if p is None:
            return []
        out = []
        for n in walk(p.root):
            if n.type in p.spec.calls:
                callee = call_name(p, n)
                if callee:
                    out.append(CallSite(callee, rel, n.start_point[0] + 1, "", ""))
        return out

    def search(self, pattern: str, limit: int = 30) -> list[tuple[str, int, str]]:
        rx = re.compile(pattern)
        hits = []
        for rel in self.files():
            for i, text in enumerate(self.lines(rel) or [], 1):
                if rx.search(text):
                    hits.append((rel, i, text.strip()[:200]))
                    if len(hits) >= limit:
                        return hits
        return hits


def numbered(lines: list[str], start: int, end: int, marks: dict[int, str] | None = None) -> str:
    marks = marks or {}
    end = min(end, len(lines))
    width = len(str(end))
    return "\n".join(f"{marks.get(n, ''):>10} {n:>{width}} | {lines[n - 1]}" for n in range(start, end + 1))
