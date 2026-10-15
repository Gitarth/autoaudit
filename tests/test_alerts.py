import json
import os
import shutil
from pathlib import Path

import pytest

from autoaudit import alerts, crawl, joern, projects
from autoaudit.context import build_context

# A CodeQL-shaped SARIF result: rule found by index, CWE in tags, file: URIs.
CODEQL = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "rules": [
                        {
                            "id": "java/sql-injection",
                            "properties": {
                                "tags": ["security", "external/cwe/cwe-089"],
                                "security-severity": "8.8",
                            },
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleIndex": 0,
                    "message": {"text": "Query built from user input"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "file:///repo/src/A.java"},
                                "region": {"startLine": 9},
                            }
                        }
                    ],
                    "codeFlows": [
                        {
                            "threadFlows": [
                                {
                                    "locations": [
                                        {
                                            "location": {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "file:///repo/src/A.java"},
                                                    "region": {"startLine": 3},
                                                },
                                                "message": {"text": "getParameter(...)"},
                                            }
                                        },
                                        {
                                            "location": {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "file:///repo/src/A.java"},
                                                    "region": {"startLine": 9},
                                                },
                                                "message": {"text": "sql"},
                                            }
                                        },
                                    ]
                                }
                            ]
                        }
                    ],
                }
            ],
        }
    ],
}


def test_read_codeql_style_sarif(tmp_path):
    p = tmp_path / "proj.sarif"
    p.write_text(json.dumps(CODEQL))
    [a] = alerts.read_sarif(p, strip_prefix="/repo")
    assert (a.tool, a.rule_id, a.project) == ("CodeQL", "java/sql-injection", "proj")
    assert a.cwes == ["CWE-89"]
    assert a.severity == "8.8"
    assert (a.path, a.line) == ("src/A.java", 9)
    assert [(s.path, s.line, s.code) for s in a.flow] == [
        ("src/A.java", 3, "getParameter(...)"),
        ("src/A.java", 9, "sql"),
    ]


def test_alert_ids_are_stable_and_round_trip(tmp_path):
    p = tmp_path / "proj.sarif"
    p.write_text(json.dumps(CODEQL))
    first = alerts.read_sarif(p)
    alerts.write_jsonl(first, tmp_path / "a.jsonl")
    again = alerts.read_jsonl(tmp_path / "a.jsonl")
    assert [a.id for a in again] == [a.id for a in first] == [a.id for a in alerts.read_sarif(p)]
    assert again[0].flow == first[0].flow


def test_relative_uris_are_kept_relative(tmp_path):
    doc = json.loads(json.dumps(CODEQL))
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    loc["uri"] = "./src/A.java"
    p = tmp_path / "x.sarif"
    p.write_text(json.dumps(doc))
    assert alerts.read_sarif(p)[0].path == "src/A.java"


# --------------------------------------------------------------- joern spec
SPEC = {
    "rules": [
        {
            "id": "sqli",
            "name": "SQL injection",
            "cwe": "CWE-89",
            "severity": "error",
            "sources": [
                {"kind": "call", "pattern": ".*getParameter.*"},
                {"kind": "annotated_param", "pattern": "RequestParam"},
            ],
            "sinks": [{"pattern": "executeQuery", "arg": 1}],
            "sanitizers": [{"pattern": ".*escapeSql.*"}],
        }
    ]
}


def test_spec_to_tsv():
    joern.validate_spec(SPEC)
    assert joern.spec_to_tsv(SPEC).splitlines() == [
        "SOURCE\tsqli\tcall\t.*getParameter.*",
        "SOURCE\tsqli\tannotated_param\tRequestParam",
        "SINK\tsqli\tcall\texecuteQuery\t1",
        "SANITIZER\tsqli\tcall\t.*escapeSql.*",
    ]


@pytest.mark.parametrize(
    "mutate,msg",
    [
        (lambda r: r.update(id="bad id"), "bad rule id"),
        (lambda r: r.update(sinks=[]), "at least one source and one sink"),
        (lambda r: r["sources"].append({"kind": "nope", "pattern": "x"}), "unknown source kind"),
        (lambda r: r["sinks"].append({"pattern": "a(", "arg": "*"}), "invalid sink pattern"),
        (lambda r: r["sinks"].append({"pattern": "a\tb"}), "multi-line"),
        (lambda r: r["sinks"].append({"pattern": "x", "arg": "first"}), "sink arg"),
    ],
)
def test_spec_validation(mutate, msg):
    spec = json.loads(json.dumps(SPEC))
    mutate(spec["rules"][0])
    with pytest.raises(joern.SpecError, match=msg):
        joern.validate_spec(spec)


def test_bundled_specs_are_valid():
    specs = sorted((Path(joern.__file__).parent.parent / "specs").glob("*.json"))
    assert specs
    for p in specs:
        joern.load_spec(p)


FLOWS = [
    {
        "rule": "sqli",
        "flow": [
            {"file": "src/A.java", "line": 3, "method": "A.handle:void()", "code": 'getParameter("q")'},
            {"file": "src/B.java", "line": 7, "method": "B.build:java.lang.String()", "code": "s"},
            {"file": "src/A.java", "line": 9, "method": "A.handle:void()", "code": "sql"},
        ],
    }
]


def test_joern_flows_round_trip_through_sarif(tmp_path):
    p = tmp_path / "shop.sarif"
    p.write_text(json.dumps(joern.to_sarif(FLOWS, SPEC)))
    [a] = alerts.read_sarif(p)
    assert (a.tool, a.rule_id, a.cwes, a.severity) == ("autoaudit-joern", "sqli", ["CWE-89"], "error")
    assert (a.path, a.line, a.function) == ("src/A.java", 9, "A.handle:void()")
    assert [s.path for s in a.flow] == ["src/A.java", "src/B.java", "src/A.java"]
    assert "getParameter" in a.message


# ------------------------------------------------------------------ context
def test_context_marks_flow_steps_across_files(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/A.java").write_text("\n".join(f"a{i}" for i in range(1, 31)))
    (tmp_path / "src/B.java").write_text("\n".join(f"b{i}" for i in range(1, 11)))
    p = tmp_path / "shop.sarif"
    p.write_text(json.dumps(joern.to_sarif(FLOWS, SPEC)))
    [a] = alerts.read_sarif(p)
    text = build_context(a, tmp_path, window=1)
    assert text.index("### src/A.java") < text.index("### src/B.java")  # flow order
    assert "[1]  3 | a3" in text
    assert "[3,SINK]  9 | a9" in text
    assert "[2]  7 | b7" in text
    assert "a20" not in text  # outside every window
    assert "    ..." in text  # gap between merged windows


def test_context_never_reads_outside_root(tmp_path):
    (tmp_path / "secret.txt").write_text("TOPSECRET")
    root = tmp_path / "repo"
    root.mkdir()
    a = alerts.Alert(tool="t", rule_id="r", message="", project="p", path="../secret.txt", line=1)
    assert "TOPSECRET" not in build_context(a, root)


def test_source_roots_skip_archive_wrapper(tmp_path):
    (tmp_path / "o__a" / "a-sha").mkdir(parents=True)
    (tmp_path / "o__b" / "src").mkdir(parents=True)
    (tmp_path / "o__b" / "pom.xml").write_text("")
    assert projects.source_roots(tmp_path) == [
        ("o__a", tmp_path / "o__a" / "a-sha"),
        ("o__b", tmp_path / "o__b"),
    ]


def test_license_of():
    assert crawl.license_of({"license": {"spdx_id": "MIT"}}) == "MIT"
    assert crawl.license_of({"license": {"spdx_id": "NOASSERTION"}}) == "NOASSERTION"
    assert crawl.license_of({"license": None}) == "NOASSERTION"


# -------------------------------------------- integration (needs real Joern)
JOERN = os.environ.get("AUTOAUDIT_TEST_JOERN_HOME")

JAVA = """package app;
import java.sql.*;
import javax.servlet.http.HttpServletRequest;
public class Users {
    Connection conn;
    String build(String n) { return "SELECT * FROM u WHERE n='" + n + "'"; }
    public void vulnerable(HttpServletRequest req) throws Exception {
        String sql = build(req.getParameter("n"));
        conn.createStatement().executeQuery(sql);
    }
    public void sanitized(HttpServletRequest req) throws Exception {
        String n = Encoder.escapeSql(req.getParameter("n"));
        conn.createStatement().executeQuery("SELECT * FROM u WHERE n='" + n + "'");
    }
    public void constant() throws Exception {
        conn.createStatement().executeQuery("SELECT 1");
    }
}
"""


@pytest.mark.skipif(not JOERN, reason="set AUTOAUDIT_TEST_JOERN_HOME to a dir with joern + joern-parse")
def test_joern_end_to_end(tmp_path):
    src = tmp_path / "src" / "app"
    src.mkdir(parents=True)
    (src / "Users.java").write_text(JAVA)
    n = joern.scan(
        tmp_path / "src",
        joern.load_spec(joern.DEFAULT_SPEC),
        tmp_path / "out" / "demo.sarif",
        tmp_path / "cpg",
        bin_dir=Path(JOERN),
        timeout=600,
    )
    found = alerts.read_sarif(tmp_path / "out" / "demo.sarif")
    assert n == len(found) == 1  # interprocedural, sanitizer respected
    assert found[0].rule_id == "sqli"
    assert found[0].line == 9
    assert any(s.function and "build" in s.function for s in found[0].flow)
    shutil.rmtree(tmp_path / "cpg", ignore_errors=True)
