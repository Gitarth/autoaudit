"""The collection model must prune only what it can prove, so most tests here are
cases where it has to stay silent."""

import pytest

from autoaudit import codeindex, feasibility
from autoaudit.alerts import Alert, Step

pytest.importorskip("tree_sitter_java")

JAVA_TEMPLATE = """class T {{
    String f(String param) {{
        String bar = "init";
{body}
        return run(bar);
    }}
    String run(String s) {{ return s; }}
    void use(java.util.List<String> l) {{ }}
}}
"""

LIST = """        java.util.List<String> l = new java.util.ArrayList<String>();
        l.add("safe");
        l.add(param);
        l.add("moresafe");
        l.remove(0);
        bar = l.get({i});"""

MAP = """        java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>();
        m.put("keyA", "a_Value");
        m.put("keyB", param);
        bar = (String) m.get("keyB");
        bar = (String) m.get("{key}");"""


def check(tmp_path, source: str, read_marker: str, ext="java", sink_marker="return run(bar)"):
    path = f"src/T.{ext}"
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / path).write_text(source)
    lines = source.splitlines()
    read = next(i for i, ln in enumerate(lines, 1) if read_marker in ln)
    sink = next(i for i, ln in enumerate(lines, 1) if sink_marker in ln)
    a = Alert(tool="t", rule_id="r", message="", project="p", path=path, line=sink, flow=[Step(path, read)])
    return feasibility.infeasible(a, codeindex.CodeIndex(tmp_path))


def java(body):
    return JAVA_TEMPLATE.format(body=body)


def test_list_constant_element_is_pruned(tmp_path):
    d = check(tmp_path, java(LIST.format(i=1)), "l.get(")
    assert d is not None and "'moresafe'" in d.reason and "<non-constant>" in d.reason


def test_list_tainted_element_is_kept(tmp_path):
    assert check(tmp_path, java(LIST.format(i=0)), "l.get(") is None


def test_map_overwrite_with_constant_is_pruned(tmp_path):
    d = check(tmp_path, java(MAP.format(key="keyA")), 'm.get("keyA")')
    assert d is not None and "'a_Value'" in d.reason


def test_map_tainted_key_is_kept(tmp_path):
    body = MAP.format(key="keyB").replace('bar = (String) m.get("keyB");\n', "", 1)
    assert check(tmp_path, java(body), 'm.get("keyB")') is None


def test_missing_map_key_is_null(tmp_path):
    d = check(tmp_path, java(MAP.format(key="nope")), 'm.get("nope")')
    assert d is not None and "None" in d.reason


@pytest.mark.parametrize(
    "mutation",
    [
        "use(l);",  # escapes into another method
        "for (int k = 0; k < 1; k++) { l.add(param); }",  # mutation in a loop
        "if (param.isEmpty()) { l.remove(0); }",  # mutation in a branch
        "l.add(0, param);",  # positional insert is not modelled
        "l.set(1, param);",  # unknown method
        "l = new java.util.ArrayList<String>();",  # collection variable reassigned
    ],
)
def test_unmodelled_usage_makes_the_model_silent(tmp_path, mutation):
    body = LIST.format(i=1).replace("        l.remove(0);", f"        l.remove(0);\n        {mutation}")
    assert check(tmp_path, java(body), "l.get(") is None


def test_unknown_key_could_overwrite_anything(tmp_path):
    body = MAP.format(key="keyA").replace('m.put("keyB", param);', "m.put(param, param);")
    assert check(tmp_path, java(body), 'm.get("keyA")') is None


def test_impure_read_is_not_pruned(tmp_path):
    body = LIST.format(i=1).replace("bar = l.get(1);", "bar = l.get(1) + param;")
    assert check(tmp_path, java(body), "l.get(") is None


def test_later_tainted_write_keeps_the_alert(tmp_path):
    body = LIST.format(i=1) + "\n        if (param.length() > 3) bar = param;"
    assert check(tmp_path, java(body), "l.get(") is None


def test_used_tainted_write_is_not_killed(tmp_path):
    body = MAP.format(key="keyA").replace(
        'bar = (String) m.get("keyB");', 'bar = (String) m.get("keyB");\n        run(bar);'
    )
    assert check(tmp_path, java(body), 'm.get("keyA")') is None


PY = """def f(request):
    param = request.args.get("q")
    l = []
    l.append("safe")
    l.append(param)
    l.append("moresafe")
    l.pop(0)
    bar = l[{i}]
    d = {{}}
    d["a"] = "x"
    d["b"] = param
    baz = d.get("{key}")
    return run(bar, baz)
"""

JS = """function f(req) {{
  const param = req.query.q;
  const a = [];
  a.push("safe", param);
  a.shift();
  a.push("tail");
  const bar = a[{i}];
  const m = new Map();
  m.set("k", param);
  const baz = m.get("{key}");
  return run(bar, baz);
}}
"""


@pytest.mark.parametrize("i,pruned", [(1, True), (0, False), (-1, True)])
def test_python_list(tmp_path, i, pruned):
    assert (check(tmp_path, PY.format(i=i, key="b"), "bar = l[", "py", "return run") is not None) is pruned


@pytest.mark.parametrize("key,pruned", [("a", True), ("b", False), ("zzz", True)])
def test_python_dict_get(tmp_path, key, pruned):
    assert (check(tmp_path, PY.format(i=0, key=key), "baz = d.get", "py", "return run") is not None) is pruned


def test_python_missing_subscript_raises_so_is_not_modelled(tmp_path):
    src = PY.format(i=0, key="b").replace('baz = d.get("b")', 'baz = d["zzz"]')
    assert check(tmp_path, src, "baz = d[", "py", "return run") is None


@pytest.mark.parametrize(
    "i,key,marker,pruned",
    [
        (1, "k", "const bar", True),  # ["param", "tail"][1]
        (0, "k", "const bar", False),
        (0, "other", "const baz", True),  # Map.get of a missing key -> undefined
        (0, "k", "const baz", False),
    ],
)
def test_javascript_array_and_map(tmp_path, i, key, marker, pruned):
    src = JS.format(i=i, key=key)
    assert (check(tmp_path, src, marker, "js", "return run") is not None) is pruned
