"""
Helpers for code2vec's .c2v format: `label ctx ctx ...` where each context is
`token,path,token`.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path


def iter_paths(line: str) -> Iterator[tuple[str, str]]:
    """Yield (label, context) for every non-empty context on a .c2v line."""
    parts = line.split()
    if not parts:
        return
    label, contexts = parts[0], parts[1:]
    for ctx in contexts:
        if ctx.count(",") == 2:
            yield label, ctx


def extract_paths(c2v_file: Path, out_file: Path) -> int:
    """Write one `label context` line per path context. Returns the count."""
    n = 0
    with open(c2v_file, encoding="utf-8") as src, open(out_file, "w", encoding="utf-8") as dst:
        for line in src:
            for label, ctx in iter_paths(line):
                dst.write(f"{label} {ctx}\n")
                n += 1
    return n
