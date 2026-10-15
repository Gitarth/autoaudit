import json
import shutil
import subprocess

import pytest

from autoaudit import bench, mine

pytestmark = pytest.mark.skipif(
    not (shutil.which("opengrep") or shutil.which("semgrep")), reason="needs opengrep or semgrep"
)

VULN = """from flask import Flask, request
import os
app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args["host"]
    os.system("ping -c1 " + host)
    return "ok"

@app.route("/other")
def other():
    os.system("echo " + request.args["x"])
    return "ok"
"""
FIXED = VULN.replace('    os.system("ping -c1 " + host)\n', '    subprocess.run(["ping", "-c1", host])\n')


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _repo(tmp_path, fixed_text):
    repo = tmp_path / "upstream"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    _git(repo, "config", "uploadpack.allowAnySHA1InWant", "true")
    (repo / "app.py").write_text(VULN)
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "v1")
    (repo / "app.py").write_text(fixed_text)
    _git(repo, "commit", "-qam", "fix")
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True
    ).stdout.strip()
    return bench.Case(name="app", repo=repo.as_uri(), fix=sha, cwe="CWE-78", language="python")


def test_identified_and_fixed_case_becomes_examples(tmp_path):
    pytest.importorskip("tree_sitter_python")
    case = _repo(tmp_path, FIXED)
    out = tmp_path / "out"
    summary = mine.mine([case], out, workers=1, timeout=300)
    row = json.loads((out / "cases.jsonl").read_text())
    assert row["status"] == "identified" and row["real"] == 1 and row["weak_false"] == 1, row
    recs = [json.loads(line) for line in (out / "dataset.jsonl").read_text().splitlines()]
    assert sorted(r["label"] for r in recs) == [False, True]
    assert {r["label_source"] for r in recs} == {"fix", "persists"}
    assert all(r["graph"] and r["group"] == case.repo and r["language"] == "python" for r in recs)
    assert summary["real_examples"] == 1
    assert not (out / "work0" / "repos" / "app").exists()  # checkouts are deleted
    # resumable: a second run skips the case
    assert mine.mine([case], out, workers=1)["cases_tried"] == 1


def test_fix_the_scanner_never_flagged_is_not_kept(tmp_path):
    case = _repo(tmp_path, VULN.replace("ok", "OK"))  # the "fix" changes no sink
    out = tmp_path / "out"
    mine.mine([case], out, workers=1, timeout=300)
    row = json.loads((out / "cases.jsonl").read_text())
    assert row["status"] == "not_identified"
    assert not (out / "dataset.jsonl").exists()
