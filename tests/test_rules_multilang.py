"""autoaudit's Semgrep/Opengrep rules for Python, JavaScript, Go, PHP and C#:
every line marked VULN in tests/fixtures/rules is reported, nothing else is."""

import re
import shutil
from pathlib import Path

import pytest

from autoaudit import alerts, ensemble

FIXTURES = Path(__file__).parent / "fixtures" / "rules"

pytestmark = pytest.mark.skipif(
    not (shutil.which("opengrep") or shutil.which("semgrep")), reason="needs opengrep or semgrep"
)


@pytest.fixture(scope="module")
def found(tmp_path_factory):
    src = tmp_path_factory.mktemp("src")
    for f in FIXTURES.iterdir():
        shutil.copy(f, src / f.name)
    out = ensemble.run_opengrep(src, tmp_path_factory.mktemp("out") / "rules.sarif", timeout=600)
    return alerts.read_sarif(out, project="fixtures")


def _expected() -> set[tuple[str, int, str]]:
    out = set()
    for f in FIXTURES.iterdir():
        for n, line in enumerate(f.read_text().splitlines(), 1):
            m = re.search(r"VULN (?:lib )?(\w+)", line)
            if m:
                out.add((f.name, n, m.group(1)))
    return out


KIND = {
    "sqli": "sqli",
    "cmdi": "cmdi",
    "path": "path-traversal",
    "xss": "xss",
    "code": "code-injection",
    "deser": "deserialization",
    "ssrf": "ssrf",
}


@pytest.mark.parametrize("lang", ["py", "js", "go", "php", "cs"])
def test_every_vulnerable_line_and_nothing_else(found, lang):
    exp = {(f, n, KIND[k]) for f, n, k in _expected() if f.endswith("." + lang)}
    got = {
        (a.path, a.line, re.sub(r"^autoaudit-\w+?-(lib-)?", "", a.rule_id))
        for a in found
        if a.path.endswith("." + lang)
    }
    assert got == exp


def test_rule_ids_have_no_path_prefix_and_carry_cwes(found):
    assert found and all(a.rule_id.startswith("autoaudit-") and a.cwes for a in found)
