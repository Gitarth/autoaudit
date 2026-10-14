import json
from pathlib import Path

from autoaudit import bench
from autoaudit.alerts import Alert, Step

VULN = """def view(request):
    q = request.args["q"]
    db.execute("SELECT * FROM t WHERE a = '" + q + "'")
    log(q)
    os.system("ls " + request.args["d"])
"""
FIXED = """def view(request):
    q = request.args["q"]
    db.execute("SELECT * FROM t WHERE a = ?", (q,))

    log(q)
    os.system("ls " + request.args["d"])
"""


def _alert(rule, cwe, line, src_line=2):
    return Alert("Semgrep OSS", rule, "m", "app", "a.py", line, None, None, [cwe], [Step("a.py", src_line)])


def _setup(tmp_path):
    for d, text in (("repos", VULN), ("fixed", FIXED)):
        (tmp_path / d / "app").mkdir(parents=True)
        (tmp_path / d / "app" / "a.py").write_text(text)
    truth = {
        "app": {"cwe": "CWE-89", "locations": [{"path": "a.py", "lines": [3], "functions": [[1, 3, "view"]]}]}
    }
    return truth


def test_differential_labels(tmp_path):
    truth = _setup(tmp_path)
    sqli = _alert("sqli", "CWE-89", 3)
    cmdi = _alert("cmdi", "CWE-78", 5, 5)  # survives the fix unchanged (line moved to 6)
    xss_in_fix = _alert("xss", "CWE-79", 3)  # touches the fix but has another CWE
    vuln = [sqli, cmdi, xss_in_fix]
    fixed = [_alert("cmdi", "CWE-78", 6, 6)]
    labels, stats = bench.label(
        truth, vuln, fixed, tmp_path / "repos", tmp_path / "fixed", {"app"}, tolerance=1
    )
    assert labels[sqli.id] == (True, "fix")
    assert labels[cmdi.id] == (False, "persists")
    assert xss_in_fix.id not in labels
    assert stats["app"] == {"alerts": 3, "real": 1, "false": 1, "unlabeled": 1}


def test_real_alert_that_survives_the_fix_stays_unlabeled(tmp_path):
    truth = _setup(tmp_path)
    (tmp_path / "fixed" / "app" / "a.py").write_text(VULN)  # "fix" did not change the sink
    sqli = _alert("sqli", "CWE-89", 3)
    labels, _ = bench.label(truth, [sqli], [sqli], tmp_path / "repos", tmp_path / "fixed", {"app"})
    assert labels == {}


def test_unscanned_fixed_version_gives_no_labels(tmp_path):
    truth = _setup(tmp_path)
    labels, stats = bench.label(
        truth, [_alert("sqli", "CWE-89", 3)], [], tmp_path / "repos", tmp_path / "fixed", set()
    )
    assert labels == {} and stats == {}


def test_training_corpus_is_valid():
    cases = bench.load_corpus(Path(bench.__file__).parent / "corpus" / "training.json")
    assert len(cases) >= 40
    assert {c.language for c in cases} >= {"java", "python", "javascript", "go", "php", "csharp"}
    for c in cases:
        assert len(c.fix) == 40 and c.repo.startswith("https://github.com/") and c.license
    doc = json.loads((Path(bench.__file__).parent / "corpus" / "training.json").read_text())
    assert all(
        c.get("advisory")
        or c["name"] in {"halo", "kkFileView", "jeecg-boot", "spring-cloud-function", "javamelody"}
        for c in doc["cases"]
    )
