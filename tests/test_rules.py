"""SpEL, XXE, LDAP and XPath rules: Joern spec, Semgrep rules and configuration checks."""

import os
import shutil
from pathlib import Path

import pytest

from autoaudit import alerts, codeindex, ensemble, feasibility, joern
from autoaudit.alerts import Alert

pytest.importorskip("tree_sitter_java")

APP = """import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

class App {
  void spel(HttpServletRequest request) throws Exception {
    String expr = request.getParameter("e");
    Object v = new SpelExpressionParser().parseExpression(expr).getValue();
  }
  void spelSafe(HttpServletRequest request) throws Exception {
    String expr = request.getParameter("e");
    SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
    Object v = new SpelExpressionParser().parseExpression(expr).getValue(ctx);
  }
  void xxe(HttpServletRequest request) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db = dbf.newDocumentBuilder();
    db.parse(request.getInputStream());
  }
  void xxeHardened(HttpServletRequest request) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    DocumentBuilder db = dbf.newDocumentBuilder();
    db.parse(request.getInputStream());
  }
  void ldap(HttpServletRequest request, javax.naming.directory.DirContext ctx) throws Exception {
    String user = request.getParameter("u");
    ctx.search("ou=users", "(uid=" + user + ")", new javax.naming.directory.SearchControls());
  }
  void ldapSafe(HttpServletRequest request, javax.naming.directory.DirContext ctx) throws Exception {
    String user = org.owasp.esapi.ESAPI.encoder().encodeForLDAP(request.getParameter("u"));
    ctx.search("ou=users", "(uid=" + user + ")", new javax.naming.directory.SearchControls());
  }
  void xpath(HttpServletRequest request, org.w3c.dom.Document doc) throws Exception {
    javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
    String name = request.getParameter("n");
    xp.evaluate("/users/user[@name='" + name + "']", doc);
  }
  void xpathSafe(HttpServletRequest request, org.w3c.dom.Document doc) throws Exception {
    javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
    String name = org.owasp.esapi.ESAPI.encoder().encodeForXPath(request.getParameter("n"));
    xp.evaluate("/users/user[@name='" + name + "']", doc);
  }
}
"""

LINES = APP.splitlines()


def sink(method: str, needle: str) -> int:
    start = next(i for i, ln in enumerate(LINES, 1) if f"void {method}(" in ln)
    return next(i for i, ln in enumerate(LINES[start - 1 :], start) if needle in ln)


VULNERABLE = {
    ("CWE-917", sink("spel", "parseExpression")),
    ("CWE-611", sink("xxe", "db.parse")),
    ("CWE-90", sink("ldap", "ctx.search")),
    ("CWE-643", sink("xpath", "xp.evaluate")),
}
SAFE_BY_CONFIG = {
    ("CWE-917", sink("spelSafe", "parseExpression")),
    ("CWE-611", sink("xxeHardened", "db.parse")),
}
SAFE_BY_SANITIZER = {
    ("CWE-90", sink("ldapSafe", "ctx.search")),
    ("CWE-643", sink("xpathSafe", "xp.evaluate")),
}


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/App.java").write_text(APP)
    return tmp_path


def test_spec_has_the_new_rules():
    cwes = {r["cwe"] for r in joern.load_spec(joern.DEFAULT_SPEC)["rules"]}
    assert {"CWE-917", "CWE-611", "CWE-90", "CWE-643"} <= cwes


@pytest.mark.parametrize(
    "cwe,line,expect", [(c, ln, False) for c, ln in VULNERABLE] + [(c, ln, True) for c, ln in SAFE_BY_CONFIG]
)
def test_configuration_mitigations(repo, cwe, line, expect):
    a = Alert(tool="t", rule_id="r", message="", project="p", path="App.java", line=line, cwes=[cwe])
    d = feasibility.infeasible(a, codeindex.CodeIndex(repo / "src"))
    assert (d is not None) is expect


def test_xxe_hardening_variants(tmp_path):
    def method(body):
        return f"""class X {{ void f(java.io.InputStream in) throws Exception {{
{body}
  }} }}"""

    cases = {
        'dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);\n'
        'dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);': True,
        'dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);': False,
        'dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);': False,
        "": False,
    }
    for i, (setup, safe) in enumerate(cases.items()):
        src = method(
            "javax.xml.parsers.DocumentBuilderFactory dbf = "
            "javax.xml.parsers.DocumentBuilderFactory.newInstance();\n"
            f"{setup}\njavax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();\ndb.parse(in);"
        )
        d = tmp_path / str(i)
        d.mkdir()
        (d / "X.java").write_text(src)
        line = next(n for n, ln in enumerate(src.splitlines(), 1) if "db.parse" in ln)
        a = Alert(
            tool="t", rule_id="xxe", message="", project="p", path="X.java", line=line, cwes=["CWE-611"]
        )
        assert (feasibility.infeasible(a, codeindex.CodeIndex(d)) is not None) is safe, setup


JOERN = os.environ.get("AUTOAUDIT_TEST_JOERN_HOME")


@pytest.mark.skipif(not JOERN, reason="set AUTOAUDIT_TEST_JOERN_HOME to a dir with joern + joern-parse")
def test_joern_finds_new_classes(repo):
    spec = joern.load_spec(joern.DEFAULT_SPEC)
    joern.scan(repo / "src", spec, repo / "out/app.sarif", repo / "cpg", Path(JOERN), "java", 900)
    found = alerts.read_sarif(repo / "out/app.sarif")
    got = {(c, a.line) for a in found for c in a.cwes}
    assert VULNERABLE | SAFE_BY_CONFIG <= got  # config-mitigated ones are found, then pruned
    assert not (SAFE_BY_SANITIZER & got)  # ESAPI encoders stop the flow
    idx = codeindex.CodeIndex(repo / "src")
    kept = {(c, a.line) for a in found if feasibility.infeasible(a, idx) is None for c in a.cwes}
    assert VULNERABLE <= kept and not (SAFE_BY_CONFIG & kept)


@pytest.mark.skipif(
    not (shutil.which("opengrep") or shutil.which("semgrep")), reason="opengrep/semgrep not installed"
)
def test_semgrep_rules_find_new_classes(repo):
    out = ensemble.run_opengrep(repo / "src", repo / "app.opengrep.sarif", timeout=600)
    got = {(c, a.line) for a in alerts.read_sarif(out, project="app") for c in a.cwes}
    assert VULNERABLE <= got
    assert not (SAFE_BY_SANITIZER & got)
