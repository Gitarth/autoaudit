import csv
import json

from autoaudit import dataset


def test_build_extracts_every_category(fpr_path, tmp_path):
    out = tmp_path / "ds"
    summary = dataset.build([fpr_path], out)
    rows = dataset.read_rows(out / "findings.jsonl")

    # V1, V2, V5 are audited .java findings; V3 is unaudited, V4 is a .jsp.
    assert sorted(r["instance_id"] for r in rows) == ["V1", "V2", "V5"]
    # Old code exhausted the index iterator after the first category.
    assert set(summary["categories"]) == {"SQL Injection", "Cross-Site Scripting: Reflected"}
    assert summary["labels"] == {"Not an Issue": 1, "Suspicious": 2}


def test_sources_stored_once_by_hash(fpr_path, tmp_path):
    out = tmp_path / "ds"
    dataset.build([fpr_path], out)
    rows = dataset.read_rows(out / "findings.jsonl")
    assert len({r["source_sha"] for r in rows}) == 1  # all in A.java
    assert len(list((out / "sources").iterdir())) == 1


def test_conflicting_labels_are_reported(fpr_path, tmp_path):
    summary = dataset.build([fpr_path], tmp_path / "ds")
    # V1 (Not an Issue) and V5 (Suspicious): same file, same category.
    assert summary["file_category_pairs_with_conflicting_labels"] == 1


def test_corrupt_fpr_is_skipped(fpr_path, tmp_path):
    bad = tmp_path / "bad.fpr"
    bad.write_bytes(b"not a zip")
    summary = dataset.build([bad, fpr_path], tmp_path / "ds")
    assert summary["findings"] == 3
    assert "error" in summary["fprs"][0]


def _row(project, sha, label="Suspicious"):
    return {
        "project": project,
        "source_sha": sha,
        "analysis": label,
        "category": "X",
        "line": 1,
        "instance_id": f"{project}-{sha}",
    }


def test_projects_sharing_a_file_share_a_group():
    rows = [_row("a", "s1"), _row("b", "s1"), _row("c", "s2"), _row("d", "s3"), _row("c", "s3")]
    g = dataset.leakage_groups(rows)
    assert g["a"] == g["b"]
    assert g["c"] == g["d"]
    assert g["a"] != g["c"]


def test_split_never_puts_a_project_or_shared_file_in_two_splits(tmp_path):
    rows = [_row(f"p{i}", f"s{i}") for i in range(200)]
    rows += [_row("p0", "shared"), _row("p150", "shared")]
    result = dataset.split(rows, tmp_path / "splits", seed=1)
    seen = {}
    for name in ("train", "val", "test"):
        for r in dataset.read_rows(tmp_path / "splits" / f"{name}.jsonl"):
            for key in (r["project"], r["source_sha"]):
                assert seen.setdefault(key, name) == name
    assert sum(v["findings"] for v in result.values()) == len(rows)
    assert result["train"]["findings"] > result["test"]["findings"] > 0


def test_split_is_deterministic(tmp_path):
    rows = [_row(f"p{i}", f"s{i}") for i in range(50)]
    a = dataset.split(rows, tmp_path / "a", seed=3)
    b = dataset.split(rows, tmp_path / "b", seed=3)
    assert a == b
    assert (tmp_path / "a/train.jsonl").read_text() == (tmp_path / "b/train.jsonl").read_text()


def test_labels_csv_is_valid_csv(fpr_path, tmp_path):
    out = tmp_path / "ds"
    dataset.build([fpr_path], out)
    dataset.split(dataset.read_rows(out / "findings.jsonl"), out / "splits", (1.0, 0.0, 0.0))
    with open(out / "splits/train_labels.csv", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert {r["label"] for r in rows} == {"Suspicious", "Not an Issue"}
    assert all((out / r["source"]).exists() for r in rows)
    json.loads((out / "summary.json").read_text())
