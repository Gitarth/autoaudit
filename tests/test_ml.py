import json
import random

import pytest

from autoaudit import cli, codeindex, evaluate
from autoaudit.alerts import Alert, Step, write_jsonl
from autoaudit.ml import data, features, graph

pytest.importorskip("tree_sitter_java")

SRC = """import javax.servlet.http.HttpServletRequest;
class A {
  void direct(HttpServletRequest request) throws Exception {
    String param = request.getParameter("q");
    String cmd = "ls " + param;
    Runtime.getRuntime().exec(cmd);
  }
  void renamed(HttpServletRequest req) throws Exception {
    String value = req.getParameter("other");
    String c = "ls " + value;
    Runtime.getRuntime().exec(c);
  }
  void viaHelper(HttpServletRequest request) throws Exception {
    String v = helper(request.getParameter("q"));
    if (v.length() > 3) {
      Runtime.getRuntime().exec(v);
    }
  }
  String helper(String s) { return s.trim(); }
}
"""


def _alert(rel, src_line, mid_line, sink_line, fn="direct"):
    flow = [Step(rel, src_line, fn, None), Step(rel, mid_line, fn, None), Step(rel, sink_line, fn, None)]
    return Alert("joern", "cmdi", "m", "p", rel, sink_line, fn, "error", ["CWE-78"], flow)


@pytest.fixture
def index(tmp_path):
    (tmp_path / "A.java").write_text(SRC)
    return codeindex.CodeIndex(tmp_path)


def test_graph_structure(index):
    a = _alert("A.java", 4, 5, 6)
    g = graph.build_graph(a, index)
    n = len(g["x"])
    assert n > 10 and all(len(row) == 3 + graph.N_FLAGS for row in g["x"])
    assert all(0 <= s < n and 0 <= d < n and 0 <= t < len(graph.EDGE_TYPES) for s, d, t in g["e"])
    types = {t for _, _, t in g["e"]}
    assert {graph.AST, graph.NEXT, graph.TOKEN, graph.USE, graph.FLOW} <= types
    sink = [row for row in g["x"] if row[4]]
    assert sink and all(row[3] for row in sink)  # sink nodes are on the flow
    assert any(row[5] for row in g["x"])  # source marked


def test_graph_abstracts_names_and_literals(index):
    g1 = graph.build_graph(_alert("A.java", 4, 5, 6), index)
    g2 = graph.build_graph(_alert("A.java", 9, 10, 11, "renamed"), index)
    # same structure, different variable names and string literal: identical node labels
    strip = lambda g: [row[:3] for row in g["x"][1:]]  # noqa: E731 - the method name node differs
    assert strip(g1) == strip(g2)
    toks = {graph.stable_hash(t) for t in ("call:getParameter", "call:exec", "VAR", "STR", "type:String")}
    assert toks <= {row[1] for row in g1["x"]}


def test_graph_call_edge_to_helper(index):
    a = _alert("A.java", 13, 13, 15, "viaHelper")
    a.flow.insert(1, Step("A.java", 19, "helper", None))
    g = graph.build_graph(a, index)
    assert any(t == graph.CALL for _, _, t in g["e"])


def test_kinds_are_coarse_and_shared():
    k = lambda t: graph.KINDS[graph.kind_of(t)]  # noqa: E731
    assert k("method_invocation") == k("call_expression") == k("call") == "call"
    assert k("identifier") == "identifier" and k("modifiers") == "other"
    assert k("formal_parameter") == "parameter" and k("if_statement") == k("elif_clause") == "if"
    assert k("boolean_operator") == "binary"


def test_slice_group_ignores_names(index):
    g1 = features.slice_group(_alert("A.java", 4, 5, 6), index)
    g2 = features.slice_group(_alert("A.java", 9, 10, 11, "renamed"), index)
    g3 = features.slice_group(_alert("A.java", 13, 13, 15, "viaHelper"), index)
    assert g1 == g2 != g3


def test_features(index):
    f = features.features(_alert("A.java", 13, 13, 15, "viaHelper"), index)
    assert f["cwe=CWE-78"] == 1 and f["tool=joern"] == 1 and f["n_tools"] == 1
    assert f["sink_guards"] == 1 and f["fn_if"] == 1 and f["path_len_max"] == 3
    assert f["call=exec"] == 1 and f["ast_dead"] == 0


def test_dataset_cli_and_labels(tmp_path, index):
    alerts = [_alert("A.java", 4, 5, 6), _alert("A.java", 9, 10, 11, "renamed")]
    write_jsonl(alerts, tmp_path / "alerts.jsonl")
    (tmp_path / "labels.csv").write_text(f"alert_id,label\n{alerts[0].id},true\n")
    tri = tmp_path / "triage.jsonl"
    tri.write_text(
        json.dumps({"alert_id": alerts[1].id, "verdict": "false_positive", "provider": "anthropic"})
        + "\n"
        + json.dumps({"alert_id": alerts[0].id, "verdict": "false_positive", "provider": "ast"})
        + "\n"
    )
    out = tmp_path / "ds.jsonl.gz"
    cli.main(
        ["--data-dir", str(tmp_path), "ml-dataset", "--src", str(index.root), "--labels",
         str(tmp_path / "labels.csv"), "--triage", str(tri), "--out", str(out)]
    )  # fmt: skip
    recs = {r["alert_id"]: r for r in data.read(out)}
    assert recs[alerts[0].id]["label"] is True and recs[alerts[0].id]["label_source"] == "hand"
    assert recs[alerts[1].id]["label"] is False and recs[alerts[1].id]["label_source"] == "triage"
    assert recs[alerts[0].id]["graph"]["x"]


def _synthetic(n=80, seed=0):
    """Graphs where real findings have an extra marked node pattern; features agree."""
    rng = random.Random(seed)
    recs = []
    for i in range(n):
        y = i % 2
        nodes = [[rng.randrange(50), rng.randrange(50), rng.randrange(5), 0, 0, 0, 1] for _ in range(12)]
        if y:
            nodes += [[7, 7, 1, 1, 1, 0, 1], [8, 8, 1, 1, 0, 1, 1]]
        edges = [[j, j + 1, j % 3] for j in range(len(nodes) - 1)]
        recs.append(
            {
                "alert_id": f"a{i}",
                "project": "p",
                "rule_id": "r",
                "cwes": ["CWE-78" if i % 4 < 2 else "CWE-89"],
                "path": f"F{i}.java",
                "line": 1,
                "label": bool(y),
                "group": f"g{i // 2}",
                "features": {"x": y + rng.random() * 0.1, "noise": rng.random()},
                "graph": {"x": nodes, "e": edges},
            }
        )
    return recs


def test_threshold_keeps_target_recall():
    from autoaudit.ml import models

    probs = [0.1, 0.2, 0.3, 0.4, 0.9, 0.05]
    labels = [1, 1, 1, 1, 0, 0]
    t = models.threshold_for_recall(probs, labels, 0.75)
    assert sum(p >= t for p, y in zip(probs, labels) if y) >= 3


def test_gbdt_cv_and_predict_roundtrip(tmp_path):
    pytest.importorskip("sklearn")
    recs = _synthetic()
    ds = tmp_path / "ds.jsonl"
    data.write(recs, ds)
    model_dir, oof = tmp_path / "model", tmp_path / "oof.jsonl"
    cli.main(
        ["ml-train", "--dataset", str(ds), "--model", "gbdt", "--cv", "random", "grouped", "cwe",
         "--folds", "4", "--oof-out", str(oof), "--out", str(model_dir)]
    )  # fmt: skip
    meta = json.loads((model_dir / "meta.json").read_text())
    assert meta["kind"] == "gbdt" and meta["cv"]["cv_grouped"]["auc"] > 0.9
    verdicts = evaluate.read_triage(oof)
    assert len(verdicts) == len(recs) and {r["provider"] for r in verdicts.values()} == {"model"}

    from autoaudit.ml import models

    model, meta = models.load(model_dir)
    probs = model.predict(recs)
    assert sum((p >= 0.5) == r["label"] for p, r in zip(probs, recs)) >= 0.9 * len(recs)


def test_ggnn_learns_graph_pattern(tmp_path):
    pytest.importorskip("sklearn")
    pytest.importorskip("torch")
    from autoaudit.ml import models

    recs = _synthetic(60)
    for r in recs:
        r["features"] = {"noise": 0.0}  # only the graph carries the signal
    y = [int(r["label"]) for r in recs]
    m = models.make("ggnn", epochs=40, hidden=16, steps=2, patience=40).fit(recs, y)
    probs = m.predict(recs)
    assert sum((p >= 0.5) == bool(t) for p, t in zip(probs, y)) >= 0.9 * len(y)
    models.save(m, tmp_path / "g", {"threshold": 0.5})
    m2, meta = models.load(tmp_path / "g")
    assert meta["kind"] == "ggnn"
    assert m2.predict(recs[:5]) == pytest.approx(probs[:5], abs=1e-5)
    h = models.make("hybrid", epochs=2, hidden=8, steps=1).fit(recs, y)
    assert len(h.predict(recs[:3])) == 3


def test_ml_predict_keeps_existing_verdicts(tmp_path, index):
    pytest.importorskip("sklearn")
    from autoaudit.ml import models

    alerts = [_alert("A.java", 4, 5, 6), _alert("A.java", 9, 10, 11, "renamed")]
    write_jsonl(alerts, tmp_path / "alerts.jsonl")
    recs = _synthetic()
    m = models.make("gbdt").fit(recs, [int(r["label"]) for r in recs])
    models.save(m, tmp_path / "model", {"threshold": 0.5})
    out = tmp_path / "triage.jsonl"
    out.write_text(
        json.dumps({"alert_id": alerts[0].id, "verdict": "false_positive", "provider": "ast"}) + "\n"
    )
    cli.main(
        ["--data-dir", str(tmp_path), "ml-predict", "--model", str(tmp_path / "model"),
         "--src", str(index.root), "--out", str(out)]
    )  # fmt: skip
    got = evaluate.read_triage(out)
    assert got[alerts[0].id]["provider"] == "ast"  # pruning verdict not overridden
    assert got[alerts[1].id]["provider"] == "model"
