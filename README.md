# autoaudit

Builds a labeled dataset of static-analysis findings for training
false-positive classifiers. It crawls Java projects from GitHub, scans them
with Fortify, and turns your **audit verdicts** (`Suspicious` vs.
`Not an Issue` by default) into samples that point at the exact source
file, line and enclosing method.

Originally written for a SANS master's research paper (the version used in
the paper is commit `d674af2`). Version 2 is a rewrite that fixes several
data-quality bugs in the original pipeline; see [Changes in 2.0](#changes-in-20).

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

Python 3.9+. External tools are only needed for the steps that use them:
Fortify SCA (`scan`), Java and the [CK](https://github.com/mauricioaniche/ck)
jar (`metrics`, available as the `ck` submodule).

## Pipeline

All artifacts go under `--data-dir` (default `./data`, or `AUTOAUDIT_DATA_DIR`).

```bash
export GITHUB_TOKEN=...                     # never hardcode tokens

autoaudit crawl --query "language:Java webapp" --limit 400   # -> downloads/, repos.csv (with commit SHAs)
autoaudit extract                                            # -> repos/<project>/, lists Maven projects
autoaudit scan --command "sh mvn-run.sh {project_dir} {name}" --timeout 3600
                                                             # -> fprs/, scan_results.csv, scan_logs/
# ... audit the FPRs in Fortify Audit Workbench ...
autoaudit stats data/fprs                                    # verdict counts per FPR (CSV)
autoaudit build data/fprs                                    # -> dataset/findings.jsonl, sources/, summary.json
autoaudit split --ratios 0.8 0.1 0.1 --seed 0                # -> dataset/splits/{train,val,test}.jsonl + _labels.csv
autoaudit metrics --ck-jar ck/target/ck-*-jar-with-dependencies.jar   # CK metrics + total LOC
autoaudit c2v-paths file.c2v                                 # one labeled path context per line
```

### Dataset format

`findings.jsonl` holds one row per audited finding:

| field | meaning |
|---|---|
| `project`, `instance_id` | FPR name and Fortify instance ID |
| `analysis` | audit verdict, read from the Analysis tag by its ID |
| `category`, `type`, `subtype`, `kingdom` | Fortify category |
| `path`, `line` | primary (sink) location of the finding |
| `function`, `function_line` | enclosing method, when Fortify records it |
| `severity`, `confidence` | Fortify instance severity / confidence |
| `source_sha` | file content stored at `sources/<sha>.java` |

`summary.json` reports label balance and
`file_category_pairs_with_conflicting_labels`, meaning files that carry both
verdicts for the same category. These are a sign that whole-file inputs are too
coarse, and method- or line-level samples should be used instead.

### Leakage-safe splits

`split` assigns whole projects to train/val/test, and projects that contain
any byte-identical file (forks, vendored code, copies) are kept in the same
split. A random per-file split lets the same code appear on both sides
and inflates test scores.

## Changes in 2.0

Fixes to the original scripts that affect the data:

- **All categories are extracted.** The source index iterator was consumed
  by the first category, so later categories got no files.
- **Labels come from the Analysis tag ID**, not "the second `<Value>`",
  which picked up custom tags or crashed on issues with one tag.
- **Findings point to the sink** (`isDefault` trace node), not the first
  trace node (often the taint source in another file); line and method
  are kept.
- **Bad zips no longer duplicate the previous project** during extraction.
- **Scan status uses the exit code and a fresh FPR.** Previously every
  project counted as successful and successes were double-counted.
- **GitHub search really sorts by stars** (`sort=`, not `s=`), page math
  is correct, downloads follow the default branch and are pinned to a SHA.
- **Issue counts are read from the FPR directly** (no Python 2 script).
- No hardcoded paths or credentials, and repeated runs no longer append duplicates.

## Development

```bash
pytest
ruff check . && ruff format --check .
```
