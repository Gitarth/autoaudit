"""
Code metrics via CK (https://github.com/mauricioaniche/ck).

Note: CK computes static metrics (LOC, CBO, WMC, ...), not test coverage.
"""

from __future__ import annotations

import csv
import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)


def run_ck(ck_jar: Path, projects: list[tuple[str, Path]], out_dir: Path) -> dict[str, int]:
    """Run CK once per project; output goes to out_dir/<name>/. Returns exit codes."""
    codes = {}
    for name, project_dir in projects:
        dest = out_dir / name
        dest.mkdir(parents=True, exist_ok=True)
        # CK 0.6.x writes its CSVs into the working directory; newer versions
        # take an output dir as the 5th argument. Running in dest covers both.
        proc = subprocess.run(
            [
                "java",
                "-jar",
                str(ck_jar.resolve()),
                str(project_dir.resolve()),
                "false",
                "0",
                "false",
                str(dest.resolve()) + "/",
            ],
            cwd=dest,
            capture_output=True,
            text=True,
        )
        codes[name] = proc.returncode
        if proc.returncode:
            log.warning("CK failed for %s: %s", name, proc.stderr.strip()[-500:])
    return codes


def total_loc(metrics_dir: Path) -> dict[str, int]:
    """Sum the `loc` column of every <project>/class.csv."""
    totals = {}
    for class_csv in sorted(metrics_dir.glob("*/class.csv")):
        with open(class_csv, newline="", encoding="utf-8") as fh:
            totals[class_csv.parent.name] = sum(
                int(r["loc"]) for r in csv.DictReader(fh) if r.get("loc", "").isdigit()
            )
    return totals
