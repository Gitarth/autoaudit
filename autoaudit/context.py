"""
Build the code context an analyst (or an LLM) needs to judge one alert:
the lines around every step of the source-to-sink flow, merged per file,
with each flow step marked. Works for any language because it only needs
paths and line numbers.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from .alerts import Alert


def _read_lines(root: Path, rel: str, cache: dict) -> list[str] | None:
    if rel not in cache:
        p = (root / rel).resolve()
        try:
            p.relative_to(root.resolve())  # never read outside the repository
            cache[rel] = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except (OSError, ValueError):
            cache[rel] = None
    return cache[rel]


def _merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for lo, hi in sorted(ranges):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def build_context(alert: Alert, root: Path, window: int = 6, max_chars: int = 24_000) -> str:
    """Render the flow as annotated snippets. Steps are numbered [1], [2], ...;
    the alert's primary location is marked [SINK]."""
    steps = [(s.path, s.line) for s in alert.flow if s.line]
    marks: dict[tuple[str, int], list[str]] = defaultdict(list)
    for i, key in enumerate(steps, 1):
        marks[key].append(str(i))
    if alert.line:
        marks[(alert.path, alert.line)].append("SINK")
        if (alert.path, alert.line) not in steps:
            steps.append((alert.path, alert.line))

    by_file: dict[str, list[tuple[int, int]]] = defaultdict(list)
    order: list[str] = []
    for path, line in steps:
        if path not in by_file:
            order.append(path)
        by_file[path].append((max(1, line - window), line + window))

    cache: dict = {}
    parts = []
    for path in order:
        lines = _read_lines(root, path, cache)
        if lines is None:
            parts.append(f"### {path}\n(source not available)")
            continue
        width = len(str(len(lines)))
        chunk = [f"### {path}"]
        for lo, hi in _merge(by_file[path]):
            hi = min(hi, len(lines))
            if chunk[-1] != f"### {path}":
                chunk.append("    ...")
            for n in range(lo, hi + 1):
                tag = marks.get((path, n))
                prefix = f"[{','.join(tag)}]" if tag else ""
                chunk.append(f"{prefix:>10} {n:>{width}} | {lines[n - 1]}")
        parts.append("\n".join(chunk))

    text = "\n\n".join(parts)
    if len(text) > max_chars:
        text = text[: max_chars - 40] + "\n... (context truncated)"
    return text
