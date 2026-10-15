import json
import subprocess

import pytest

from autoaudit import bench, cli, codeindex
from autoaudit.alerts import Alert, Step

VULN = """package demo;

import java.io.File;

public class Files {
    public File open(String name) {
        File f = new File("/data", name);
        return f;
    }

    public int other() {
        return 1;
    }
}
"""

FIXED = """package demo;

import java.io.File;
import java.io.IOException;

public class Files {
    public File open(String name) throws IOException {
        File f = new File("/data", name);
        if (!f.getCanonicalPath().startsWith("/data/")) {
            throw new IOException("traversal");
        }
        return f;
    }

    public int other() {
        return 1;
    }
}
"""


def _git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def upstream(tmp_path):
    """A repository with a vulnerable commit, its fix (plus a test change), and a later commit."""
    repo = tmp_path / "upstream"
    (repo / "src/main/java/demo").mkdir(parents=True)
    (repo / "src/test/java/demo").mkdir(parents=True)
    _git("init", "-q", cwd=repo)
    for k, v in {
        "user.email": "t@example.com",
        "user.name": "t",
        "uploadpack.allowAnySHA1InWant": "true",
    }.items():
        _git("config", k, v, cwd=repo)
    src = repo / "src/main/java/demo/Files.java"
    test = repo / "src/test/java/demo/FilesTest.java"
    src.write_text(VULN)
    test.write_text("class FilesTest {}\n")
    _git("add", ".", cwd=repo)
    _git("commit", "-q", "-m", "vulnerable", cwd=repo)
    src.write_text(FIXED)
    test.write_text("class FilesTest { void traversal() {} }\n")
    _git("commit", "-q", "-am", "fix traversal", cwd=repo)
    fix = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True
    ).stdout.strip()
    (repo / "README").write_text("later\n")
    _git("add", ".", cwd=repo)
    _git("commit", "-q", "-m", "later", cwd=repo)
    return repo, fix


# ------------------------------------------------------------------ diff -> truth
DIFF = """diff --git a/A.java b/A.java
index 1..2 100644
--- a/A.java
+++ b/A.java
@@ -3,0 +4 @@ import x;
+import y;
@@ -10,2 +11,2 @@ class A {
--- old SQL comment that looks like a header
-        run(q);
+-- new
+        run(sanitize(q));
@@ -20 +21,3 @@ class A {
-
+        if (bad(p)) {
+            return;
+        }
diff --git a/New.java b/New.java
new file mode 100644
--- /dev/null
+++ b/New.java
@@ -0,0 +1 @@
+class New {}
"""


def test_hunks_parse_old_side_and_ignore_new_files():
    hs = bench.hunks(DIFF)
    assert list(hs) == ["A.java"]  # removed lines starting with "--" are not file headers
    assert [(h.start, h.count) for h in hs["A.java"]] == [(3, 0), (10, 2), (20, 1)]
    assert hs["A.java"][2].added[0].strip() == "if (bad(p)) {"


def test_truth_lines_skip_noise_and_widen_insertions():
    text = [f"        stmt{n};" for n in range(1, 31)]
    text[2] = "import x;"  # line 3
    text[19] = ""  # line 20: blank line replaced by code
    text[20] = "    }"  # line 21: brace, skipped
    h_import, h_change, h_insert = bench.hunks(DIFF)["A.java"]
    assert bench.truth_lines(h_import, text) == set()  # only an import was added
    assert bench.truth_lines(h_change, text) == {10, 11}
    assert bench.truth_lines(h_insert, text) == {19, 22}  # nearest code on either side


def test_is_source():
    assert bench.is_source("app/src/main/java/a/B.java")
    assert not bench.is_source("app/src/test/java/a/B.java")
    assert not bench.is_source("a/BTest.java")
    assert not bench.is_source("pom.xml")


def test_corpus_bundled_is_valid():
    cases = bench.load_corpus()
    assert len(cases) == 5
    assert all(c.cwe.startswith("CWE-") and len(c.fix) == 40 and c.repo.startswith("https://") for c in cases)


def test_corpus_rejects_dotted_names(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"cases": [{"name": "a.b", "repo": "r", "fix": "f", "cwe": "22"}]}))
    with pytest.raises(ValueError):
        bench.load_corpus(p)


# ------------------------------------------------------------------ fetch (local git)
def test_fetch_checks_out_parent_of_fix_and_derives_truth(tmp_path, upstream):
    repo, fix = upstream
    case = bench.Case(name="demo", repo=repo.as_uri(), fix=fix, cwe="CWE-22", id="DEMO-1")
    truth = bench.fetch([case], tmp_path / "bench")["demo"]

    src = tmp_path / "bench/repos/demo"
    assert (src / "src/main/java/demo/Files.java").read_text() == VULN
    assert truth["vulnerable"] != fix
    (loc,) = truth["locations"]  # the test file change is ignored
    assert loc["path"] == "src/main/java/demo/Files.java"
    assert loc["lines"] == [6, 7, 8]  # signature changed; check inserted between 7 and 8
    if codeindex.available():
        assert [f[2] for f in loc["functions"]] == ["open"]

    again = bench.fetch([case], tmp_path / "bench")["demo"]  # re-run is idempotent
    assert again == truth


def test_fetch_records_unreachable_repo(tmp_path):
    case = bench.Case(name="gone", repo=(tmp_path / "missing").as_uri(), fix="0" * 40, cwe="CWE-89")
    assert "error" in bench.fetch([case], tmp_path / "bench")["gone"]


# ------------------------------------------------------------------ scoring
TRUTH = {
    "demo": {
        "id": "DEMO-1",
        "cwe": "CWE-22",
        "locations": [{"path": "src/Files.java", "lines": [7], "functions": [[6, 9, "open"]]}],
    },
    "broken": {"error": "fetch failed"},
}


def _alert(line, cwe="CWE-22", flow=(), path="src/Files.java"):
    return Alert(
        tool="t",
        rule_id="r",
        message="",
        project="demo",
        path=path,
        line=line,
        cwes=[cwe],
        flow=[Step(p, n) for p, n in flow],
    )


def test_match_levels():
    locs = TRUTH["demo"]["locations"]
    assert bench.match(_alert(8), locs) == {"sink_line", "sink_function", "flow"}
    assert bench.match(_alert(9, flow=()), locs, tolerance=0) == {"sink_function", "flow"}
    via_flow = _alert(40, flow=[("src/Web.java", 3), ("/abs/root/src/Files.java", 6), ("src/Files.java", 40)])
    assert bench.match(via_flow, locs, tolerance=0) == {"flow"}
    assert bench.match(_alert(7, path="other/Files.java"), locs) == set()


def test_score_counts_cwe_triage_and_errors():
    hit, wrong_cwe, noise = _alert(7), _alert(7, cwe="CWE-89"), _alert(30)
    report = bench.score(TRUTH, [hit, wrong_cwe, noise])
    s = report["summary"]
    assert s["cases"] == 1 and s["detected"]["flow"] == 1 and s["alerts"] == 3
    demo = next(c for c in report["cases"] if c["name"] == "demo")
    assert list(demo["hits"]) == [hit.id] and demo["alerts_same_cwe"] == 2
    assert any("error" in c for c in report["cases"])

    assert set(bench.score(TRUTH, [hit, wrong_cwe], any_cwe=True)["cases"][0]["hits"]) == {
        hit.id,
        wrong_cwe.id,
    }

    triage = {hit.id: {"verdict": "false_positive"}, noise.id: {"verdict": "true_positive"}}
    after = bench.score(TRUTH, [hit, noise], triage)
    assert after["summary"]["detected_after_triage"]["flow"] == 0  # triage dismissed the real one
    assert after["summary"]["alerts_after_triage"] == 1
    assert "after triage" in bench.markdown(after)


def test_cli_fetch_and_score(tmp_path, upstream, capsys):
    repo, fix = upstream
    corpus = tmp_path / "corpus.json"
    corpus.write_text(
        json.dumps({"cases": [{"name": "demo", "repo": repo.as_uri(), "fix": fix, "cwe": "22"}]})
    )
    data = tmp_path / "data"
    cli.main(["--data-dir", str(data), "bench", "fetch", "--corpus", str(corpus)])
    alerts = data / "bench/alerts.jsonl"
    alerts.write_text(json.dumps(_alert(7, path="src/main/java/demo/Files.java").to_dict()) + "\n")
    cli.main(["--data-dir", str(data), "bench", "score", "--corpus", str(corpus)])
    out = capsys.readouterr().out
    assert "Detected 1/1 (flow)" in out
    assert json.loads((data / "bench/report.json").read_text())["summary"]["recall"]["sink_line"] == 1.0
