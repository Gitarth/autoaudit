import json

import pytest

from autoaudit import joern, llm, variants
from autoaudit.alerts import Alert, Step

SPEC = joern.load_spec(joern.DEFAULT_SPEC)


class Session:
    def __init__(self, *texts):
        self.texts, self.calls = list(texts), []

    def post(self, url, headers=None, json=None, timeout=None):
        self.calls.append(json)
        text = self.texts.pop(0)

        class R:
            status_code, headers = 200, {}

            def json(self):
                return {
                    "model": "m",
                    "content": [{"type": "text", "text": text}],
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                }

        return R()


def alert(i, line):
    return Alert(
        tool="t",
        rule_id="sqli",
        message="",
        project="p",
        path="Dao.java",
        line=line,
        cwes=["CWE-89"],
        flow=[Step("Dao.java", 2), Step("Dao.java", line)],
    )


def test_confirmed_from_triage_or_labels():
    a, b, c = alert(1, 4), alert(2, 5), alert(3, 6)
    triage = {a.id: {"verdict": "true_positive"}, b.id: {"verdict": "false_positive"}}
    assert [x.id for x in variants.confirmed([a, b, c], triage)] == [a.id]
    assert [x.id for x in variants.confirmed([a, b, c], None, {c.id: True, b.id: False})] == [c.id]


def test_propose_merges_validated_additions(tmp_path):
    (tmp_path / "Dao.java").write_text('class Dao {\n String q = r.getParameter("q");\n\n  runSql(q);\n}\n')
    good = {
        "rules": [
            {
                "id": "sqli-wrapper",
                "cwe": "CWE-89",
                "sources": [{"kind": "call", "pattern": "getParameter"}],
                "sinks": [{"pattern": "runSql", "arg": "1"}],
                "variant_of": ["x"],
            }
        ]
    }
    session = Session('{"rules": [{"id": "bad id!"}]}', json.dumps(good))  # first answer invalid
    p = llm.AnthropicProvider(model="m", api_key="k", session=session)
    spec, additions, usage = variants.propose([alert(1, 4)], {"p": tmp_path}, SPEC, p)
    prompt = session.calls[0]["messages"][0]["content"]
    assert "confirmed_vulnerabilities" in prompt and "runSql(q);" in prompt
    assert "previous answer was invalid" in session.calls[1]["messages"][0]["content"]
    sqli = next(r for r in spec["rules"] if r["cwe"] == "CWE-89")
    assert {"pattern": "runSql", "arg": "1"} in sqli["sinks"]
    assert len(spec["rules"]) == len(SPEC["rules"])  # merged by CWE, nothing dropped
    assert additions["rules"][0]["variant_of"] == ["x"]  # provenance kept for review
    assert all("variant_of" not in r for r in spec["rules"])
    assert usage.requests == 2


def test_propose_needs_confirmed_findings():
    with pytest.raises(ValueError):
        variants.propose([], {}, SPEC, llm.AnthropicProvider(model="m", api_key="k", session=Session()))


def test_diff_lists_only_new_locations():
    old = [alert(1, 4)]
    new = [alert(1, 4), alert(2, 9)]
    assert [a.line for a in variants.diff(old, new)] == [9]
