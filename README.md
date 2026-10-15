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

OWASP Benchmark (Java, 6 classes: SQLi, command, path traversal, XSS, LDAP,
XPath; after AST pruning, no LLM):

| Setup | TPR | FPR | Precision |
|---|---|---|---|
| Joern | 0.937 | 0.118 | 0.896 |
| Joern + Semgrep CE (union) | 0.987 | 0.244 | 0.815 |
| Joern + Semgrep CE (both agree) | 0.752 | 0.101 | 0.890 |
| Joern + sweep (first 4 classes) | 1.000 | 0.357 | 0.757 |

LDAP (CWE-90) and XPath (CWE-643) alone: TPR 1.00 at FPR 0.16 and 0.25. The
sweep and the union are high-recall modes meant to feed triage (LLM or learned).

The bundled spec also covers expression-language injection (SpEL, OGNL, MVEL,
Jakarta EL; CWE-917) and XXE (CWE-611), which Benchmark does not test. For
those two the pruner reads configuration as a reviewer would: a parser whose
factory disallows DOCTYPEs or external entities, or SpEL evaluated only with a
`SimpleEvaluationContext`, is reported as mitigated (`autoaudit/hardening.py`).

`--max-flows` (default 200 source-sink pairs per rule) protects large repos;
Joern logs a warning when it drops pairs. Benchmark needs `--max-flows 100000`.

## Learned triage (GBDT and a Devign-style graph network)

Instead of (or before) an LLM, a model trained on audited alerts can score new
ones. Needs `pip install -e ".[ml]"` (scikit-learn and PyTorch; CPU is enough).

```bash
autoaudit ml-dataset --src SRC --labels audit.csv --out data/ml.jsonl.gz    # or --owasp / --triage
autoaudit ml-train --dataset data/ml.jsonl.gz --model hybrid --cv random grouped cwe --out models/hybrid
autoaudit ml-predict --model models/hybrid --src SRC        # verdicts -> data/triage.jsonl
autoaudit eval --owasp expected.csv --triage data/triage.jsonl
```

- Each alert becomes hand-made features (path shape, conversions, sanitiser,
  collection and string calls on the path, guards around the sink, tool
  agreement, AST pruner result, call names) and a **code graph** in the style
  of Devign: the AST of every function on the reported path with statement
  order, token order, def-use, call and the analyzer's own source-to-sink
  edges. Names and literals are abstracted and node types mapped to kinds
  shared by all tree-sitter grammars, so one model can span languages.
- Models: `gbdt` (gradient-boosted trees on the features), `ggnn` (gated graph
  network on the graph alone), `hybrid` (the GGNN with the features joined
  before its classifier).
- The decision threshold keeps a target share of real findings (default 98%)
  on out-of-fold predictions; dismissing a real vulnerability costs more than
  reviewing a false one.
- Cross-validation is reported three ways: `random` (optimistic), `grouped`
  (near-identical findings, by abstracted slice, file or project, never
  straddle train and test) and `cwe` (leave one vulnerability class out).
- `ml-predict` keeps existing prune and LLM verdicts unless `--overwrite`, and
  `ml-dataset --triage` never learns from pruning or model verdicts.
- Labels: hand labels (`alert_id,label`), OWASP Benchmark expected results, or
  earlier LLM verdicts (weak labels, e.g. to distil an expensive model into a
  cheap one).

OWASP Benchmark, Joern + Semgrep union (1,372 labeled alerts, 819 real), out-of-fold:

| Model | CV | AUC | False alerts removed at 98% of real kept |
|---|---|---|---|
| gbdt | random | 0.973 | 83% |
| gbdt | grouped | 0.970 | 81% |
| gbdt | leave one class out | 0.951 | 79% |
| ggnn | grouped | 0.936 | 56% |
| hybrid | grouped | 0.991 | 92% |
| hybrid | leave one class out | 0.990 | 78% |

Scorecard with the grouped out-of-fold verdicts as triage (`ml-train --oof-out`):
AST pruning alone TPR 0.987 / FPR 0.244; gbdt 0.967 / 0.134; hybrid
0.973 / 0.062 (precision 0.944).

These are Benchmark numbers: one synthetic suite of templated servlets, so
even grouped folds share templates and the models will look worse on real
code. Train on audits of your own codebases (or the Fortify FPR dataset this
project started from) before trusting a model on a new one, and treat a model
trained here as a demonstration of the pipeline, not a product.

### A multi-language training corpus from real security fixes

`autoaudit/corpus/training.json` lists 48 open-source projects in Java,
Python, JavaScript, TypeScript, Go, PHP and C#. Each one is pinned to the
commit just before a public security fix (GitHub Security Advisories / OSV),
covering SQL, command and code injection, path traversal, XSS, XXE, SSRF,
expression injection and deserialization. Every fix commit was fetched and
checked against its advisory. The file stores references only; code is
fetched at build time under each project's own license.

```bash
autoaudit bench label --corpus autoaudit/corpus/training.json --timeout 1800   # fetch both versions, scan, label
autoaudit ml-dataset --alerts data/bench/alerts.jsonl --labels data/bench/labels.csv \
    --src-dir data/bench/repos --group project --only-labeled --out data/corpus-ml.jsonl.gz
autoaudit ml-train --dataset data/corpus-ml.jsonl.gz --model gbdt --cv grouped cwe
```

Labels come from scanning each project before and after its fix (as in D2A,
Zheng et al. 2021):

- **real** (`fix`): the alert reaches the code the fix changed, at the
  advisory's CWE, and is gone after the fix;
- **false** (`persists`, weak): the alert is away from the fix and is still
  reported after it with the same sink and source code. Most of these are
  false positives, but some may be real bugs nobody fixed; `ml-train
  --label-sources fix owasp hand` leaves them out, `bench label
  --no-weak-negatives` never writes them;
- everything else stays unlabeled. A case is labeled only when the same
  scanners produced results for both versions.

Rules for the non-Java languages are Opengrep/Semgrep taint rules
(`autoaudit/rules/*-taint.yml`); Joern runs on the Java cases. Semgrep CE does
not report taint traces, so Semgrep-only alerts carry the sink and its
function, not a path.

First build (Semgrep CE on all 48 cases): 8,443 alerts on the vulnerable
versions, yet only 5 cases had an alert of the advisory's CWE on the fixed
code (7 with any CWE), giving 4 real labels and 8,420 weak negatives (7,522
of them from one PHP project). Most of these real vulnerabilities cross
functions or files, or start from sources the rules do not model (settings,
library parameters, stored data), which intraprocedural Semgrep CE misses. So
as built, the corpus is a realistic **evaluation** set and a source of
realistic false positives; training positives need either many more cases
(OSV lists thousands of fix commits) or candidate alerts that do not depend on
taint reaching the sink (every dangerous call, as `sweep` does).

### Training on audited Fortify FPRs

```bash
autoaudit fpr-import path/to/fprs/        # -> data/fortify_alerts.jsonl, data/fortify_labels.csv, data/fortify-src/
autoaudit ml-dataset --alerts data/fortify_alerts.jsonl --labels data/fortify_labels.csv \
    --src-dir data/fortify-src --group project --only-labeled --out data/fortify-ml.jsonl.gz
autoaudit ml-train --dataset data/fortify-ml.jsonl.gz --model gbdt --cv random grouped cwe --out models/fortify-gbdt
autoaudit ml-train --dataset data/fortify-ml.jsonl.gz --model hybrid --cv grouped --out models/fortify-hybrid
```

Each audited finding becomes an alert whose flow is Fortify's primary trace,
with the sources it touches extracted from the FPR's `src-archive`. Verdicts
`Suspicious` and `Exploitable` are real, `Not an Issue` false (change with
`--positive` / `--negative`); findings with the same rule, source and sink but
opposite verdicts lose their label. Group by project: the grouped score is the
one to expect on a codebase the model has not seen. A model trained on Fortify
alerts has learned Fortify's flows; scoring Joern or Semgrep alerts with it is a
distribution shift, so check it with `eval` on labeled alerts first.

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

### Real-project benchmark (known CVEs)

```bash
autoaudit bench                  # fetch -> scan -> score, everything under data/bench/
autoaudit bench fetch            # or one stage at a time: fetch, scan, score
autoaudit bench scan --scanners joern opengrep --bin-dir ~/joern-cli
autoaudit --data-dir data/bench triage --limit 50 && autoaudit bench score   # with LLM verdicts
```

`fetch` clones each project in `autoaudit/corpus/java-cves.json` with git at
the commit just before its security fix (shallow, pinned SHAs) and derives the
ground truth from the fix itself: the code lines it changed in the vulnerable
version (for a pure insertion, the code on either side), the functions holding
them, and optional hand-written `locations` when the fix sits away from the
flow (jeecg-boot patches a blacklist; the sink is the mapper call). Test files,
imports, blank lines and braces are ignored. `scan` runs every installed
analyzer (Joern, Opengrep/Semgrep CE), merges the alerts and prunes the
infeasible ones. `score` writes `report.md` / `report.json`: per case, whether
an alert of the case's CWE hit it at three strictnesses (sink line within
`--tolerance` lines, sink inside a fixed function, or any step of the reported
path inside one), how many alerts the project produced, and the same after
triage when `data/bench/triage.jsonl` exists.

| case | CVE | CWE | fix |
|---|---|---|---|
| halo | CVE-2026-55439 | 22 path traversal | `c0de760` |
| kkFileView | (no CVE) | 22 path traversal | `b65a048` |
| jeecg-boot | CVE-2022-47105 | 89 SQL injection | `0fc374d` |
| spring-cloud-function | CVE-2022-22963 | 917 SpEL injection | `0e89ee2` |
| javamelody | CVE-2018-15531 | 611 XXE | `ef11182` |

The last two are CWEs no bundled rule targets yet: they measure rule gaps
(`diagnose`, `infer-spec`). Add cases by appending `{name, repo, fix, cwe}`
(and optionally `id`, `vulnerable`, `locations`) to the corpus or pass your
own with `--corpus`. The code is fetched for analysis only; check each
project's license before redistributing it.

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
pip install -e ".[ml]" && pytest tests/test_ml.py   # model tests skip without scikit-learn / torch
```
