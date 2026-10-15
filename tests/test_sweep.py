import pytest

from autoaudit import codeindex, feasibility, joern, sweep
from autoaudit.alerts import Alert
from autoaudit.lighttaint import LightTaint

pytest.importorskip("tree_sitter_java")

SPEC = joern.load_spec(joern.DEFAULT_SPEC)

A = """import javax.servlet.http.HttpServletRequest;
class A {
  void split(HttpServletRequest request) throws Exception {
    String param = request.getParameter("q");
    String bar = param.split(" ")[0];
    Runtime.getRuntime().exec(bar);
  }
  void sanitized(HttpServletRequest request, java.io.PrintWriter out) {
    String param = request.getParameter("q");
    String bar = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);
    out.println(bar);
  }
  void constant() throws Exception {
    String cmd = "uptime";
    Runtime.getRuntime().exec(cmd);
  }
  void unrelated(java.util.Random r) throws Exception {
    String user = "user" + r.nextInt();
    Runtime.getRuntime().exec(user);
  }
  void deadBranch(HttpServletRequest request) throws Exception {
    String param = request.getParameter("q");
    String bar;
    int num = 86;
    if ((7 * 42) - num > 200) bar = "safe";
    else bar = param;
    Runtime.getRuntime().exec(bar);
  }
  void loop(HttpServletRequest request) throws Exception {
    java.util.List<String> names = java.util.Collections.list(request.getHeaderNames());
    for (String n : names) { Runtime.getRuntime().exec(n); }
  }
  void caller(HttpServletRequest request) throws Exception {
    helper(request.getParameter("q"));
  }
  void helper(String value) throws Exception {
    Runtime.getRuntime().exec(value);
  }
  String doSomething(String x) { return "safe"; }
}
"""

B = """class B {
  String doSomething(javax.servlet.http.HttpServletRequest request) { return request.getParameter("q"); }
}
"""

C = """class C {
  void f(javax.servlet.http.HttpServletRequest request) throws Exception {
    Runtime.getRuntime().exec(doSomething("x"));
  }
  String doSomething(String x) { return "safe"; }
}
"""


def line_of(needle, nth=1, text=A):
    return [i for i, ln in enumerate(text.splitlines(), 1) if needle in ln][nth - 1]


@pytest.fixture
def repo(tmp_path):
    for name, src in (("A", A), ("B", B), ("C", C)):
        (tmp_path / f"{name}.java").write_text(src)
    return tmp_path


def test_light_taint_follows_what_joern_loses(repo):
    lt = LightTaint(codeindex.CodeIndex(repo), SPEC, "cmdi")
    hits, chains = lt.sink_flows("A.java", line_of("exec(bar)", 1))
    assert hits == ["bar"]
    assert chains == [[line_of("String param"), line_of('split(" ")[0]'), line_of("exec(bar)", 1)]]
    assert lt.sink_flows("A.java", line_of("exec(cmd)")) is None
    assert lt.sink_flows("A.java", line_of("exec(user)")) is None
    assert lt.sink_flows("A.java", line_of("exec(n)"))[0] == ["n"]  # for-each over tainted list
    assert lt.sink_flows("A.java", line_of("exec(value)"))[0] == ["value"]  # parameter tainted by caller


def test_sanitizers_are_rule_specific(repo):
    idx = codeindex.CodeIndex(repo)
    sink = line_of("out.println(bar)")
    assert LightTaint(idx, SPEC, "xss").sink_flows("A.java", sink) is None
    assert LightTaint(idx, SPEC).sink_flows("A.java", sink) is not None  # no rule: no sanitizers


def test_same_file_definition_wins_over_name_match(repo):
    # B.doSomething returns tainted data, but C calls its own (safe) doSomething.
    lt = LightTaint(codeindex.CodeIndex(repo), SPEC, "cmdi")
    assert lt.sink_flows("C.java", line_of("exec(doSomething", text=C)) is None


def test_sweep_filters_and_feasibility_applies(repo):
    idx = codeindex.CodeIndex(repo)
    sites = [
        {
            "project": "p",
            "rule": "cmdi",
            "file": "A.java",
            "line": line_of(code, nth),
            "code": "",
            "literal_args": literal,
        }
        for code, nth, literal in [
            ("exec(bar)", 1, False),
            ("exec(cmd)", 1, False),
            ("exec(user)", 1, False),
            ("exec(bar)", 2, False),
            ("exec(value)", 1, False),
            ('exec("uptime")', 1, True),
        ]
        if code != 'exec("uptime")'
    ]
    sites.append(
        {"project": "p", "rule": "cmdi", "file": "A.java", "line": 1, "code": "", "literal_args": True}
    )
    already = Alert(
        tool="joern",
        rule_id="cmdi",
        message="",
        project="p",
        path="A.java",
        line=line_of("exec(value)"),
        cwes=["CWE-78"],
    )
    found, stats = sweep.sweep(sites, [already], SPEC, {"p": idx})
    lines = {a.line for a in found}
    assert lines == {line_of("exec(bar)", 1), line_of("exec(bar)", 2)}
    assert stats["literal"] == 1 and stats["already_alerted"] == 1
    assert stats["constant arguments"] + stats["no user input in arguments"] == 2
    assert all(a.tool == sweep.TOOL and a.cwes == ["CWE-78"] and a.flow for a in found)
    dead = next(a for a in found if a.line == line_of("exec(bar)", 2))
    live = next(a for a in found if a.line == line_of("exec(bar)", 1))
    assert feasibility.infeasible(dead, idx) is not None  # prune applies to sweep flows
    assert feasibility.infeasible(live, idx) is None
