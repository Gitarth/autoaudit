import csv

import pytest

from autoaudit import alerts, cli, fortify
from autoaudit.fpr import FPR

from .conftest import ANALYSIS, AUDIT, FVDL, INDEX, make_fpr

SOURCES = {
    "src-archive/1": "class A {\n" + "\n".join(f"  // line {i}" for i in range(2, 50)) + "\n}\n",
    "src-archive/2": "class B {}\n",
    "src-archive/3": "class C {}\n",
}


def _labels(path):
    with open(path, newline="") as fh:
        return {r["alert_id"]: r["label"] == "true" for r in csv.DictReader(fh)}


def test_trace_is_parsed_in_order(fpr_path):
    with FPR.open(fpr_path) as fpr:
        by_id = {f.instance_id: f for f in fpr.findings}
    assert by_id["V1"].trace == [("src/B.java", 5), ("src/A.java", 20)]
    assert by_id["V2"].trace == [("src/A.java", 44)]  # through the node pool
    assert "trace" not in by_id["V1"].to_dict()  # dataset rows unchanged


def test_import(tmp_path):
    fpr = make_fpr(tmp_path / "demo.fpr", sources=SOURCES)
    summary = fortify.import_fprs([fpr], tmp_path / "src", tmp_path / "a.jsonl", tmp_path / "l.csv")
    found = {a.line: a for a in alerts.read_jsonl(tmp_path / "a.jsonl")}
    labels = _labels(tmp_path / "l.csv")
    # V1 Not an Issue, V2/V5 Suspicious; V3 unaudited; V4 is a JSP with no archived source
    assert set(found) == {20, 44, 30}
    assert labels[found[20].id] is False and labels[found[44].id] is True
    v1 = found[20]
    assert v1.tool == "fortify" and v1.cwes == ["CWE-89"] and v1.project == "demo"
    assert [(s.path, s.line) for s in v1.flow] == [("src/B.java", 5), ("src/A.java", 20)]
    assert found[44].flow == [] and found[44].cwes == ["CWE-79"]
    assert (tmp_path / "src" / "demo" / "src" / "A.java").exists()
    assert summary["unlabeled_skipped"] == 1 and summary["no_source"] == 1


def test_untrusted_paths_are_never_written(tmp_path):
    evil = FVDL.replace('path="src/A.java" line="20"', 'path="../../escape.java" line="20"')
    index = INDEX.replace("/build/proj/src/A.java", "/build/proj/../../escape.java")
    fpr = make_fpr(tmp_path / "evil.fpr", fvdl=evil, sources=SOURCES)
    import zipfile

    with zipfile.ZipFile(fpr, "a") as z:  # point the index at the escaping path too
        z.writestr("src-archive/index.xml", index)
    fortify.import_fprs([fpr], tmp_path / "out" / "src", tmp_path / "a.jsonl", tmp_path / "l.csv")
    assert not (tmp_path / "escape.java").exists() and not (tmp_path / "out" / "escape.java").exists()
    assert fortify.safe_rel("/etc/passwd") is None and fortify.safe_rel("C:/x") is None
    assert fortify.safe_rel("a/../b.java") == "b.java"


def test_conflicting_duplicates_lose_their_label(tmp_path):
    # V6: same rule, source and sink as V1 (Not an Issue), but audited Suspicious
    start = FVDL.index("    <Vulnerability>")
    end = FVDL.index("</Vulnerability>") + len("</Vulnerability>\n")
    dup = FVDL[:end] + FVDL[start:end].replace(">V1<", ">V6<") + FVDL[end:]
    audit = AUDIT.replace(
        "</ns2:IssueList>",
        f'<ns2:Issue instanceId="V6"><ns2:Tag id="{ANALYSIS}"><ns2:Value>Suspicious</ns2:Value>'
        "</ns2:Tag></ns2:Issue></ns2:IssueList>",
    )
    fpr = make_fpr(tmp_path / "d.fpr", fvdl=dup, audit=audit, sources=SOURCES)
    s = fortify.import_fprs([fpr], tmp_path / "src", tmp_path / "a.jsonl", tmp_path / "l.csv")
    assert s["conflicting_labels_dropped"] == 1


def test_cli_into_ml_dataset(tmp_path):
    pytest.importorskip("tree_sitter_java")
    from autoaudit.ml import data

    fprs = tmp_path / "fprs"
    fprs.mkdir()
    make_fpr(fprs / "one.fpr", sources=SOURCES)
    make_fpr(fprs / "two.fpr", sources=SOURCES)
    d = tmp_path / "data"
    cli.main(["--data-dir", str(d), "fpr-import", str(fprs)])
    cli.main(
        ["--data-dir", str(d), "ml-dataset", "--alerts", str(d / "fortify_alerts.jsonl"),
         "--labels", str(d / "fortify_labels.csv"), "--src-dir", str(d / "fortify-src"),
         "--group", "project", "--only-labeled", "--out", str(d / "ml.jsonl")]
    )  # fmt: skip
    recs = data.read(d / "ml.jsonl")
    assert len(recs) == 6 and {r["group"] for r in recs} == {"one", "two"}
    assert all(r["features"]["tool=fortify"] == 1 for r in recs)
    assert any(r["features"].get("rule=SQL Injection") for r in recs)
