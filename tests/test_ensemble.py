import json
import shutil

import pytest

from autoaudit import alerts, codeindex, ensemble, feasibility, joern
from autoaudit.alerts import Alert, Step

SPEC = joern.load_spec(joern.DEFAULT_SPEC)


def A(tool, line, cwes=("CWE-89",), flow=None, rule="r"):
    return Alert(
        tool=tool,
        rule_id=rule,
        message="",
        project="p",
        path="X.java",
        line=line,
        cwes=list(cwes),
        flow=[Step("X.java", ln) for ln in (flow or [])],
    )


def test_merge_records_agreement_and_keeps_every_path():
    joern1 = A("autoaudit-joern", 10, flow=[3, 10])
    joern2 = A("autoaudit-joern", 10, flow=[5, 10])  # same sink, another source
    sg = A("Semgrep OSS", 10, rule="autoaudit-java-sqli")
    other_cwe = A("Semgrep OSS", 10, cwes=["CWE-79"])
    elsewhere = A("Semgrep OSS", 11)
    merged = ensemble.merge([sg, joern1, joern2, other_cwe, elsewhere])
    assert len(merged) == 3
    primary = next(a for a in merged if a.line == 10 and "CWE-89" in a.cwes)
    assert primary.tool == "autoaudit-joern"  # the one with a flow wins
    assert primary.also_reported_by == ["Semgrep OSS:autoaudit-java-sqli"]
    assert sorted(tuple(s.line for s in f) for f in primary.flows) == [(3, 10), (5, 10)]


def test_merged_alert_is_pruned_only_if_every_path_is_dead(tmp_path):
    src = """class X {
  void f(javax.servlet.http.HttpServletRequest request) throws Exception {
    String param = request.getParameter("q");
    String bar;
    int num = 86;
    if ((7 * 42) - num > 200) bar = "safe";
    else bar = param;
    Runtime.getRuntime().exec(bar);
    Runtime.getRuntime().exec(param);
  }
}
"""
    (tmp_path / "X.java").write_text(src)
    idx = codeindex.CodeIndex(tmp_path)
    dead = A("autoaudit-joern", 8, ["CWE-78"], flow=[3, 7, 8])
    assert feasibility.infeasible(dead, idx) is not None
    live = A("Semgrep OSS", 8, ["CWE-78"], flow=[3, 8])  # pretend another tool saw a live path
    [merged] = ensemble.merge([dead, live])
    assert feasibility.infeasible(merged, idx) is None


def test_attach_flows_gives_flowless_alerts_a_chain(tmp_path):
    src = """class X {
  void f(javax.servlet.http.HttpServletRequest request) throws Exception {
    String q = request.getParameter("q");
    String bar = q.split(" ")[0];
    Runtime.getRuntime().exec(bar);
  }
}
"""
    (tmp_path / "X.java").write_text(src)
    a = A("Semgrep OSS", 5, ["CWE-78"])
    assert ensemble.attach_flows([a], SPEC, {"p": codeindex.CodeIndex(tmp_path)}) == 1
    assert [s.line for s in a.flow] == [3, 4, 5]


@pytest.mark.skipif(
    not (shutil.which("opengrep") or shutil.which("semgrep")), reason="opengrep/semgrep not installed"
)
def test_run_opengrep_with_bundled_rules(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/C.java").write_text("""import javax.servlet.http.HttpServletRequest;
class C {
  void f(HttpServletRequest request) throws Exception {
    String q = request.getParameter("x");
    Runtime.getRuntime().exec(q);
  }
  void g() throws Exception { Runtime.getRuntime().exec("uptime"); }
}
""")
    out = ensemble.run_opengrep(tmp_path / "src", tmp_path / "c.opengrep.sarif", timeout=600)
    found = alerts.read_sarif(out, project="c")
    assert [(a.path, a.line, a.cwes) for a in found] == [("C.java", 5, ["CWE-78"])]
    assert json.loads(out.read_text())["runs"][0]["tool"]["driver"]["name"]
