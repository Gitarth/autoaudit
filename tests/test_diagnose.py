import json

import pytest

from autoaudit import diagnose, joern
from autoaudit.alerts import Alert
from autoaudit.codeindex import CodeIndex

pytest.importorskip("tree_sitter_java")

FOUND = 'class A {{ void f(R r) {{ s.executeQuery(r.getParameter("q")); {extra} }} }}'
MISSED = 'class B {{ void f(R r) {{ t.query(r.getParameter("q"), m); {extra} }} }}'


def test_diagnose_ranks_uncovered_calls_of_missed_files(tmp_path):
    truth = []
    for i in range(4):
        (tmp_path / f"F{i}.java").write_text(FOUND.format(extra="log(1);"))
        (tmp_path / f"M{i}.java").write_text(MISSED.format(extra="log(1);"))
        truth += [diagnose.Truth(f"F{i}.java", "CWE-89", True), diagnose.Truth(f"M{i}.java", "CWE-89", True)]
    truth.append(diagnose.Truth("F0.java", "CWE-78", False))
    alerts = [
        Alert(tool="t", rule_id="sqli", message="", project="p", path=f"F{i}.java", line=1, cwes=["CWE-89"])
        for i in range(4)
    ]
    spec = joern.load_spec(joern.DEFAULT_SPEC)
    rep = diagnose.diagnose(alerts, truth, CodeIndex(tmp_path), spec)
    r = rep["CWE-89"]
    assert (r["real"], r["missed"]) == (8, 4)
    names = [c["call"] for c in r["candidates"]]
    assert names[0] == "query"  # in every miss, in no found file, matched by no rule
    assert "getParameter" not in names  # already a source
    assert "log" not in names  # equally common in found files -> low lift ...
    assert "CWE-78" not in rep  # ... and CWEs without alerts are not diagnosed


def test_read_truth_csv(tmp_path):
    p = tmp_path / "truth.csv"
    p.write_text("path,cwe,real\nsrc/A.java,89,true\nsrc/B.java,CWE-22,false\n")
    assert diagnose.read_truth(p) == [
        diagnose.Truth("src/A.java", "CWE-89", True),
        diagnose.Truth("src/B.java", "CWE-22", False),
    ]
    assert json.dumps(diagnose.format_report({"CWE-89": {"real": 1, "missed": 1, "candidates": []}}))


def test_merge_specs_only_adds_coverage():
    from autoaudit.specgen import merge_specs

    base = joern.load_spec(joern.DEFAULT_SPEC)
    extra = {
        "rules": [
            {
                "id": "sql-injection-v2",
                "cwe": "CWE-89",
                "sources": [{"kind": "call", "pattern": "getParameter"}],
                "sinks": [{"pattern": "runQuery", "arg": "1"}],
            },
            {
                "id": "ssrf",
                "cwe": "CWE-918",
                "sources": [{"kind": "call", "pattern": "getParameter"}],
                "sinks": [{"pattern": "openConnection", "arg": "*"}],
            },
        ]
    }
    merged = merge_specs(base, extra)
    sqli = next(r for r in merged["rules"] if r["id"] == "sqli")
    assert {"pattern": "runQuery", "arg": "1"} in sqli["sinks"]  # merged by CWE
    assert len(sqli["sources"]) == len(next(r for r in base["rules"] if r["id"] == "sqli")["sources"]) + 1
    assert any(r["id"] == "ssrf" for r in merged["rules"])  # new class added
    assert len(merged["rules"]) == len(base["rules"]) + 1
    assert merge_specs(merged, extra) == merged  # idempotent


def test_infer_spec_includes_evidence_and_merges(tmp_path):
    from autoaudit import llm, specgen

    (tmp_path / "A.java").write_text("class A {}")
    reply = json.dumps(
        {
            "rules": [
                {
                    "id": "x",
                    "cwe": "CWE-89",
                    "sources": [{"pattern": "getParameter"}],
                    "sinks": [{"pattern": "query", "arg": "1"}],
                }
            ]
        }
    )

    class S:
        calls = []

        def post(self, url, headers=None, json=None, timeout=None):
            S.calls.append(json)

            class R:
                status_code, headers, text = 200, {}, ""

                def json(self):
                    return {
                        "model": "m",
                        "content": [{"type": "text", "text": reply}],
                        "usage": {"input_tokens": 1, "output_tokens": 1},
                    }

            return R()

    evidence = {
        "CWE-89": {
            "real": 10,
            "missed": 4,
            "candidates": [
                {
                    "call": "query",
                    "missed_share": 1.0,
                    "found_share": 0.0,
                    "examples": ["A.java:3: t.query(sql, m);"],
                }
            ],
        }
    }
    base = joern.load_spec(joern.DEFAULT_SPEC)
    spec, _ = specgen.infer_spec(
        tmp_path, llm.AnthropicProvider(model="m", api_key="k", session=S()), base, evidence
    )
    prompt = S.calls[0]["messages"][0]["content"]
    assert "MISSED" in prompt and "t.query(sql, m);" in prompt
    assert len(spec["rules"]) == len(base["rules"])  # merged into sqli, nothing dropped
