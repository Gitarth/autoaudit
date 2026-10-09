"""
Run a Fortify scan per Maven project and collect the resulting FPRs.

The scan command is a template so any Fortify setup works, e.g.
    "sh mvn-run.sh {project_dir} {name}"
    "mvn -f {project_dir}/pom.xml com.fortify.sca.plugins.maven:sca-maven-plugin:translate ..."
A scan counts as successful only if the command exits 0 AND writes a new FPR.
"""

from __future__ import annotations

import csv
import logging
import shlex
import shutil
import subprocess
import time
from pathlib import Path

log = logging.getLogger(__name__)

RESULT_FIELDS = ["name", "project_dir", "status", "returncode", "seconds", "fpr", "log"]


def build_command(template: str, project_dir: Path, name: str) -> list[str]:
    # Split first, then substitute, so paths with spaces stay one argument.
    return [tok.format(project_dir=str(project_dir), name=name) for tok in shlex.split(template)]


def newest_fpr(project_dir: Path, pattern: str, since: float) -> Path | None:
    fprs = [p for p in project_dir.glob(pattern) if p.stat().st_mtime >= since]
    return max(fprs, key=lambda p: p.stat().st_mtime) if fprs else None


def scan_all(
    projects: list[tuple[str, Path]],
    template: str,
    out_dir: Path,
    fpr_glob: str = "target/fortify/*.fpr",
    timeout: int | None = None,
) -> list[dict]:
    fprs, logs = out_dir / "fprs", out_dir / "scan_logs"
    fprs.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    results = []
    for i, (name, project_dir) in enumerate(projects, 1):
        log.info("[%d/%d] Scanning %s", i, len(projects), name)
        log_path = logs / f"{name}.log"
        start = time.time()
        row = {"name": name, "project_dir": str(project_dir), "fpr": "", "log": str(log_path)}
        try:
            with open(log_path, "wb") as lf:
                proc = subprocess.run(
                    build_command(template, project_dir, name),
                    stdout=lf,
                    stderr=subprocess.STDOUT,
                    timeout=timeout,
                )
            row["returncode"] = proc.returncode
            fpr = newest_fpr(project_dir, fpr_glob, start)
            if proc.returncode == 0 and fpr is not None:
                dest = fprs / f"{name}.fpr"
                shutil.copy2(fpr, dest)
                row.update(status="ok", fpr=str(dest))
            else:
                row["status"] = "failed" if proc.returncode else "no_fpr"
        except subprocess.TimeoutExpired:
            row.update(status="timeout", returncode="")
        except OSError as err:
            log.error("Could not run scan for %s: %s", name, err)
            row.update(status="error", returncode="")
        row["seconds"] = round(time.time() - start, 1)
        log.info("  -> %s", row["status"])
        results.append(row)

    with open(out_dir / "scan_results.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=RESULT_FIELDS)
        w.writeheader()
        w.writerows(results)
    return results
