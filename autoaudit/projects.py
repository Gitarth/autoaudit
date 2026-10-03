"""
Unpack downloaded repositories and pick out the Maven projects to scan.
"""

from __future__ import annotations

import logging
import shutil
import zipfile
from pathlib import Path

log = logging.getLogger(__name__)


def extract(downloads: Path, dest: Path) -> dict:
    """Unzip every archive into dest/<zip stem>/. Bad archives go to downloads/bad/."""
    dest.mkdir(parents=True, exist_ok=True)
    stats = {"extracted": 0, "already_extracted": 0, "bad": 0}
    for zpath in sorted(downloads.glob("*.zip")):
        target = dest / zpath.stem
        if target.exists():
            stats["already_extracted"] += 1
            continue
        try:
            with zipfile.ZipFile(zpath) as archive:
                tmp = dest / f".{zpath.stem}.partial"
                shutil.rmtree(tmp, ignore_errors=True)
                archive.extractall(tmp)
                tmp.rename(target)
        except (zipfile.BadZipFile, OSError) as err:
            log.warning("Bad archive %s: %s", zpath.name, err)
            bad = downloads / "bad"
            bad.mkdir(exist_ok=True)
            shutil.move(str(zpath), bad / zpath.name)
            stats["bad"] += 1
            continue  # never fall through to a previous archive
        stats["extracted"] += 1
    return stats


def maven_projects(root: Path) -> list[Path]:
    """For each project directly under root, the directory of its top-most pom.xml.

    Works at any absolute depth (paths are taken relative to root) and prefers
    the aggregator pom of multi-module builds over a submodule's.
    """
    best: dict[str, Path] = {}
    for pom in root.rglob("pom.xml"):
        rel = pom.relative_to(root)
        if len(rel.parts) < 2:
            continue
        project = rel.parts[0]
        current = best.get(project)
        if (
            current is None
            or len(pom.parts) < len(current.parts)
            or (len(pom.parts) == len(current.parts) and str(pom) < str(current))
        ):
            best[project] = pom
    return [best[p].parent for p in sorted(best)]
