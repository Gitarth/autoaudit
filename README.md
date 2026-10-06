# autoaudit

Finds security vulnerabilities with language-agnostic taint analysis and
prepares each alert for triage. [Joern](https://joern.io) traces untrusted data
from sources to sinks across functions and files. Every alert, from Joern or
any SARIF-producing analyzer, is normalized into one format together with the
code along its flow, ready for an analyst or an LLM to judge.

It also still builds labeled datasets from audited Fortify FPRs (the original
research use).

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

## Taint analysis (Joern)

Requires a Joern install (`joern` and `joern-parse` on `PATH`, or `JOERN_HOME`
/ `--bin-dir`). Joern supports Java, C/C++, C#, Go, JavaScript, Kotlin, PHP,
Python, Ruby and Swift; the language is auto-detected.

```bash
autoaudit crawl --query "language:Java webapp" --limit 200   # licenses logged in repos.csv
autoaudit extract
autoaudit joern                                  # every project -> data/sarif/<project>.sarif
autoaudit joern --src path/to/repo --spec my-rules.json      # one repo, custom rules
autoaudit alerts data/sarif                      # any SARIF (Joern, CodeQL, Opengrep...) -> data/alerts.jsonl
autoaudit context <alert-id>                     # the numbered source->sink code for one alert
```

Rules live in a JSON spec (sources, sinks, sanitizers as regexes over call
names / fully qualified method names); see `autoaudit/specs/java.json` and the
docstring in `autoaudit/joern/__init__.py`. Specs are data, so they can be
written per codebase (for example inferred by an LLM) instead of maintained as
global rule packs.

## LLM triage and rule inference (bring your own key)

Works with the Anthropic API and any OpenAI-compatible Chat Completions API
(OpenAI, Azure OpenAI, vLLM, Ollama, LM Studio, OpenRouter, ...). Keys are read
only from environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or the
variable named by `--api-key-env`), never from arguments.

```bash
export ANTHROPIC_API_KEY=...                     # the client's key
autoaudit triage --limit 50                      # try a sample first
autoaudit triage --workers 8 --price-in <usd/Mtok> --price-out <usd/Mtok> --budget-usd 20
autoaudit triage --provider openai --base-url http://localhost:11434/v1 --model qwen2.5-coder
autoaudit infer-spec --src path/to/repo --base autoaudit/specs/java.json --out data/specs/repo.json
autoaudit joern --src path/to/repo --spec data/specs/repo.json
```

- `triage` sends each alert's flow context (`autoaudit context`) and asks for a
  verdict (`true_positive` / `false_positive` / `uncertain`), confidence and
  reason. Results append to `data/triage.jsonl` and are cached by model, prompt
  version and code, so re-runs only pay for new or changed alerts. Failed calls
  are logged and retried on the next run.
- The audited code is treated as untrusted: it is fenced with a random
  delimiter and the model is told to ignore instructions inside it.
- `infer-spec` grounds the model in the repository's manifests, imports and
  entry-point code and validates the returned spec before use.
- `--budget-usd` stops starting new requests once the estimated spend (from
  your `--price-in/--price-out`) is reached. Token usage is always reported.

## Triage like a human: AST features

`pip install -e ".[ast]"` adds tree-sitter grammars (bundled, no runtime
downloads) for Java, Python, JavaScript/TypeScript, Go, PHP and C#.

- **`autoaudit prune`** removes alerts whose every reported path is provably
  impossible, the way a reviewer rules them out by reading the function:
  - a branch whose condition is constant, or a `switch` case never selected;
  - a read from a local list or map that always returns a constant (e.g.
    `l.remove(0); bar = l.get(1)` or `bar = map.get("safeKey")`), found by
    replaying the collection's operations (Java collections, Python
    list/dict, JavaScript arrays and `Map`).

  It is conservative: it gives up when a collection escapes, is mutated in a
  loop or branch, or uses an unmodelled method, and it keeps the alert when
  another write could still carry taint (e.g. switch fall-through). No LLM, no
  cost; `triage` does this automatically before calling the model.
- **`autoaudit triage --mode agent`** lets the model investigate like a
  reviewer. It starts from every function on the path (comments stripped,
  since comments are untrusted and can leak or plant answers) plus AST facts
  (guarding conditions, constant locals), and can call `read_function`,
  `find_definition`, `find_callers`, `search_code` and `read_lines` before
  giving a verdict that cites evidence lines. `--max-turns` bounds the tool
  use per alert.

On OWASP Benchmark (Java, bundled spec), Joern finds TPR 0.905 at FPR 0.576
(precision 0.635); the deterministic prune step (a few seconds, no LLM) brings
that to TPR 0.905 / FPR 0.113 (precision 0.899, score +0.792) without losing a
real vulnerability, by removing provably infeasible flows (constant collection
reads, constant ifs, constant switches). These checks were designed while studying Benchmark's
false positives, so expect smaller gains on real code; the remaining false
positives (sanitizers, parameterized queries) are left to LLM triage.

## Finding more real vulnerabilities (recall)

| Command | What it does |
|---|---|
| `autoaudit diagnose --src SRC --owasp expected.csv` (or `--truth path,cwe,real CSV`) | Ranks calls typical of **missed** real vulnerabilities that no rule covers: rule gaps, with example lines. |
| `autoaudit infer-spec --src SRC --base specs/java.json --evidence diagnose.json --out spec.json` | LLM writes rules for this codebase, guided by the diagnose report; merged into the base so coverage only grows. |
| `autoaudit summarize-libs data/sarif --out sem.tsv` then `autoaudit joern --semantics sem.tsv` | LLM classifies library calls on flows; hashes/lengths/parses stop taint (Joern semantics), class-specific sanitizers go into the spec. Sources and sinks are never suppressed. |
| `autoaudit sweep data/sarif --src SRC` | Dangerous calls no flow reaches, kept only if an argument syntactically derives from user input (`lighttaint`); alerts carry approximate flows, so `prune` applies. |
| `autoaudit opengrep --src SRC` + `autoaudit alerts data/sarif --src SRC` | Runs Opengrep/Semgrep CE with autoaudit's own rules (no telemetry) and merges with Joern: duplicates combined, agreement in `also_reported_by`, flows attached to flow-less alerts. `eval --min-tools 2` scores corroborated alerts. |
| `autoaudit variants --triage triage.jsonl --out spec2.json` + `autoaudit alerts-diff old new` | LLM generalises confirmed findings into new rules; rescan and diff to list sibling vulnerabilities. |
| `autoaudit confirm --triage triage.jsonl` (experimental) | LLM writes a harness that drives the real code with a payload; it runs in a locked-down container and an oracle it cannot fake decides (canary file, planted secret, reflected payload). |

OWASP Benchmark (Java, after AST pruning, no LLM):

| Setup | TPR | FPR | Precision |
|---|---|---|---|
| Joern | 0.933 | 0.113 | 0.902 |
| Joern + sweep | 1.000 | 0.357 | 0.757 |
| Joern + Semgrep CE (union) | 0.986 | 0.245 | 0.817 |
| Joern + Semgrep CE (both agree) | 0.745 | 0.098 | 0.894 |

The sweep and the union are high-recall modes meant to feed LLM triage.

## Evaluation

```bash
autoaudit eval --owasp BenchmarkJava/expectedresults-1.2.csv --triage data/triage.jsonl
autoaudit eval --labels my-audit.csv --triage data/triage.jsonl     # alert_id,label
```

Reports the Benchmark scorecard (TPR, FPR, TPR-FPR per CWE) for the scanner
alone and after triage, plus alert-level triage accuracy: false alerts removed
and real alerts wrongly dismissed. Treat Benchmark as a development set; it is
synthetic and GPL-2.0 licensed, so do not ship it.

`crawl --allow-license MIT Apache-2.0 ...` restricts downloads to the given
SPDX licenses; without it every repository is downloaded and its license is
recorded.

## Fortify dataset pipeline

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
AUTOAUDIT_TEST_JOERN_HOME=/path/to/joern pytest   # also run the real-Joern integration test
```
