import json
import os
from pathlib import Path

import pytest

from autoaudit import joern, libsum, llm

SPEC = joern.load_spec(joern.DEFAULT_SPEC)
EXTERNALS = {
    "<unresolvedNamespace>.digest:<unresolvedSignature>(1)": 5,
    "org.owasp.esapi.Encoder.encodeForHTML:java.lang.String(java.lang.String)": 3,
    "<unresolvedNamespace>.wrap:<unresolvedSignature>(1)": 2,
    "javax.servlet.http.HttpServletRequest.getParameter:<unresolvedSignature>(1)": 9,  # a source
    "java.lang.Runtime.exec:java.lang.Process(java.lang.String)": 4,  # a sink
    "<operator>.addition": 7,
}


class Session:
    def __init__(self, text):
        self.text, self.calls = text, []

    def post(self, url, headers=None, json=None, timeout=None):
        self.calls.append(json)
        text = self.text

        class R:
            status_code, headers = 200, {}

            def json(self):
                return {
                    "model": "m",
                    "content": [{"type": "text", "text": text}],
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                }

        return R()


def answer():
    return json.dumps(
        {
            "summaries": [
                {
                    "method": "<unresolvedNamespace>.digest:<unresolvedSignature>(1)",
                    "flow": "none",
                    "reason": "hash",
                },
                {
                    "method": "org.owasp.esapi.Encoder.encodeForHTML:java.lang.String(java.lang.String)",
                    "flow": "sanitizes",
                    "cwes": ["CWE-79"],
                    "reason": "html encoding",
                },
                {"method": "<unresolvedNamespace>.wrap:<unresolvedSignature>(1)", "flow": "propagates"},
                # the model tries to suppress a sink it was never asked about: must be ignored
                {"method": "java.lang.Runtime.exec:java.lang.Process(java.lang.String)", "flow": "none"},
            ]
        }
    )


def test_summarize_never_sends_or_suppresses_sources_and_sinks(tmp_path):
    session = Session(answer())
    p = llm.AnthropicProvider(model="m", api_key="k", session=session)
    results, usage = libsum.summarize(EXTERNALS, SPEC, p)
    sent = session.calls[0]["messages"][0]["content"]
    assert "digest" in sent and "getParameter" not in sent and "Runtime.exec" not in sent
    assert "<operator>" not in sent
    assert {r["method"].split(":")[0].rsplit(".", 1)[-1]: r["flow"] for r in results} == {
        "digest": "none",
        "encodeForHTML": "sanitizes",
        "wrap": "propagates",
    }

    out = tmp_path / "sem.tsv"
    spec2 = libsum.write_outputs(results, SPEC, out)
    rules = [ln for ln in out.read_text().splitlines() if ln and not ln.startswith("#")]
    assert rules == [libsum.quote("<unresolvedNamespace>.digest:<unresolvedSignature>(1)") + "\t"]
    xss = next(r for r in spec2["rules"] if r["cwe"] == "CWE-79")
    sqli = next(r for r in spec2["rules"] if r["cwe"] == "CWE-89")
    assert any("encodeForHTML" in s["pattern"] for s in xss["sanitizers"])
    assert not any("encodeForHTML" in s["pattern"] for s in sqli["sanitizers"])  # class-specific


def test_read_externals_sums_counts(tmp_path):
    (tmp_path / "a.externals.tsv").write_text("x.f:v()\t2\ny.g:v()\t1\n")
    (tmp_path / "b.externals.tsv").write_text("x.f:v()\t3\n")
    assert libsum.read_externals(sorted(tmp_path.glob("*.tsv"))) == {"x.f:v()": 5, "y.g:v()": 1}


JOERN = os.environ.get("AUTOAUDIT_TEST_JOERN_HOME")
JAVA = """import javax.servlet.http.HttpServletRequest;
class C {
  void f(HttpServletRequest request) throws Exception {
    String safe = com.acme.Util.digest(request.getParameter("x"));
    Runtime.getRuntime().exec(safe);
  }
  void g(HttpServletRequest request) throws Exception {
    Runtime.getRuntime().exec(com.acme.Util.wrap(request.getParameter("x")));
  }
  void h() throws Exception { Runtime.getRuntime().exec("uptime"); }
}
"""


@pytest.mark.skipif(not JOERN, reason="set AUTOAUDIT_TEST_JOERN_HOME to a dir with joern + joern-parse")
def test_summaries_change_joern_flows(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/C.java").write_text(JAVA)

    def run(out, sem=None):
        return joern.scan(
            tmp_path / "src", SPEC, out, tmp_path / "cpg", Path(JOERN), "java", 600, semantics=sem
        )

    assert run(tmp_path / "a" / "c.sarif") == 2
    externals = libsum.read_externals([tmp_path / "a" / "c.externals.tsv"])
    assert any("digest" in m for m in externals) and any("wrap" in m for m in externals)
    sinks = [json.loads(ln) for ln in (tmp_path / "a" / "c.sinks.jsonl").read_text().splitlines()]
    cmdi = {s["line"]: s["literal_args"] for s in sinks if s["rule"] == "cmdi"}
    assert cmdi == {5: False, 8: False, 10: True}

    session = Session(
        json.dumps(
            {
                "summaries": [
                    {"method": m, "flow": "none" if "digest" in m else "propagates"} for m in externals
                ]
            }
        )
    )
    results, _ = libsum.summarize(
        externals, SPEC, llm.AnthropicProvider(model="m", api_key="k", session=session)
    )
    libsum.write_outputs(results, SPEC, tmp_path / "sem.tsv")
    assert run(tmp_path / "b" / "c.sarif", tmp_path / "sem.tsv") == 1  # digest flow suppressed
