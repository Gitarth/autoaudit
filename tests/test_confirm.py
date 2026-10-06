import json
import shutil
import subprocess

import pytest

from autoaudit import confirm, llm
from autoaudit.alerts import Alert, Step

APP = """import html, os, shlex, subprocess

def ping(request):
    host = request.args.get("host")
    return subprocess.run("echo " + host, shell=True, capture_output=True, text=True).stdout

def ping_safe(request):
    host = shlex.quote(request.args.get("host"))
    return subprocess.run("echo " + host, shell=True, capture_output=True, text=True).stdout

def read(request):
    base = os.environ.get("AUTOAUDIT_BASEDIR", ".")
    with open(os.path.join(base, request.args.get("f"))) as fh:
        return fh.read()

def read_safe(request):
    base = os.environ.get("AUTOAUDIT_BASEDIR", ".")
    with open(os.path.join(base, os.path.basename(request.args.get("f")))) as fh:
        return fh.read()

def greet(request):
    return "<p>" + request.args.get("n") + "</p>"

def greet_safe(request):
    return "<p>" + html.escape(request.args.get("n")) + "</p>"
"""

HARNESS = """import os, sys
sys.path.insert(0, os.environ["PROJECT_ROOT"])
import app

class Args:
    def get(self, key):
        return os.environ["AUTOAUDIT_PAYLOAD"]

class Request:
    args = Args()

try:
    print(app.{fn}(Request()))
except Exception as err:
    print("error:", err)
"""


class Session:
    def __init__(self, text):
        self.text = text

    def post(self, url, headers=None, json=None, timeout=None):
        text = self.text

        class R:
            status_code, headers = 200, {}

            def json(self):
                return {
                    "model": "m",
                    "content": [{"type": "text", "text": text}],
                    "usage": {"input_tokens": 5, "output_tokens": 5},
                }

        return R()


def provider_for(fn):
    return llm.AnthropicProvider(
        model="m", api_key="k", session=Session(json.dumps({"code": HARNESS.format(fn=fn), "notes": "n"}))
    )


def alert(fn_line, cwe):
    return Alert(
        tool="t",
        rule_id="r",
        message="",
        project="p",
        path="app.py",
        line=fn_line,
        cwes=[cwe],
        flow=[Step("app.py", fn_line)],
    )


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(APP)
    return root


def line_of(name):
    return next(i for i, ln in enumerate(APP.splitlines(), 1) if ln.startswith(f"def {name}("))


@pytest.mark.parametrize(
    "fn,cwe,expected",
    [
        ("ping", "CWE-78", "confirmed"),
        ("ping_safe", "CWE-78", "not_confirmed"),
        ("read", "CWE-22", "confirmed"),
        ("read_safe", "CWE-22", "not_confirmed"),
        ("greet", "CWE-79", "confirmed"),
        ("greet_safe", "CWE-79", "not_confirmed"),
    ],
)
def test_oracles_locally(project, tmp_path, fn, cwe, expected):
    res = confirm.confirm(
        alert(line_of(fn), cwe), project, provider_for(fn), tmp_path / "work", sandbox="local", timeout=60
    )
    assert res.status == expected, res.stdout_tail


def test_harness_that_embeds_the_evidence_is_rejected(project, tmp_path, monkeypatch):
    monkeypatch.setattr(confirm.secrets, "token_hex", lambda n: "f00d" * (n // 2))
    cheat = json.dumps({"code": "print('<script>aaf00df00df00df00d()</script>')"})
    p = llm.AnthropicProvider(model="m", api_key="k", session=Session(cheat))
    res = confirm.confirm(alert(line_of("greet_safe"), "CWE-79"), project, p, tmp_path / "w", sandbox="local")
    assert res.status == "rejected"


def test_local_run_gets_no_secrets_from_the_environment(project, tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    leak = json.dumps({"code": "import os\nprint(os.environ.get('ANTHROPIC_API_KEY'))"})
    p = llm.AnthropicProvider(model="m", api_key="k", session=Session(leak))
    res = confirm.confirm(alert(line_of("greet"), "CWE-79"), project, p, tmp_path / "w", sandbox="local")
    assert "sk-secret" not in res.stdout_tail


def test_unsupported_and_no_container_refusal(project, tmp_path, monkeypatch):
    a = Alert(tool="t", rule_id="r", message="", project="p", path="x.rb", line=1, cwes=["CWE-78"])
    assert confirm.confirm(a, project, provider_for("ping"), tmp_path / "w").status == "unsupported"
    monkeypatch.setattr(confirm.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="refusing"):
        confirm.run_harness(
            "print(1)", "python", confirm.plan("CWE-79", tmp_path), project, tmp_path, sandbox="auto"
        )


def test_container_command_is_locked_down(project, tmp_path):
    cmd = confirm._sandbox_cmd(confirm.RUNTIMES["python"], project, tmp_path, {"A": "1"}, None, "docker")
    for flag in ("--network", "none", "--read-only", "--pids-limit", "--memory"):
        assert flag in cmd
    assert f"{project.resolve()}:/project:ro" in cmd


def _docker_ok():
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@pytest.mark.skipif(not _docker_ok(), reason="docker daemon not available")
@pytest.mark.parametrize(
    "fn,cwe,expected",
    [
        ("ping", "CWE-78", "confirmed"),
        ("ping_safe", "CWE-78", "not_confirmed"),
        ("read", "CWE-22", "confirmed"),
    ],
)
def test_oracles_in_container(project, tmp_path, fn, cwe, expected):
    res = confirm.confirm(
        alert(line_of(fn), cwe),
        project,
        provider_for(fn),
        tmp_path / "work",
        sandbox="container",
        timeout=300,
    )
    assert res.status == expected, res.stdout_tail
