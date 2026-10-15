import io
import sys
import zipfile

import pytest

from autoaudit import c2v, crawl, metrics, projects, scan


# ------------------------------------------------------------------- crawl
@pytest.mark.parametrize("count,pages", [(0, 0), (50, 1), (100, 1), (150, 2), (999, 10), (5000, 10)])
def test_pages_needed(count, pages):
    assert crawl.pages_needed(count) == pages  # old code: 50 -> 0, 999 -> 9


class FakeResponse:
    def __init__(self, payload=None, body=b"", status=200):
        self._payload, self._body, self.status_code = payload, body, status
        self.headers = {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests

            raise requests.HTTPError(str(self.status_code))

    def iter_content(self, chunk_size):
        yield self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


class FakeSession:
    def __init__(self, repos):
        self.headers, self.repos, self.calls = {}, repos, []

    def get(self, url, params=None, stream=False, timeout=None):
        self.calls.append((url, params))
        if "search/repositories" in url:
            page = params["page"]
            return FakeResponse(
                {"total_count": len(self.repos), "items": self.repos[(page - 1) * 100 : page * 100]}
            )
        if "/commits/" in url:
            return FakeResponse({"sha": "abc123" + url.rsplit("/", 1)[-1]})
        return FakeResponse(body=b"PK zip bytes")


def _repo(i, **kw):
    return {
        "full_name": f"o/r{i}",
        "size": 500,
        "stargazers_count": 1000 - i,
        "default_branch": "main" if i % 2 else "master",
        "fork": False,
        **kw,
    }


def test_crawl_sorts_by_stars_pins_sha_and_skips_forks(tmp_path):
    repos = [_repo(i) for i in range(150)] + [_repo(999, fork=True), _repo(998, size=1)]
    session = FakeSession(repos)
    rows = crawl.crawl(tmp_path, "language:Java", limit=1000, gh=crawl.GitHub(token="t", session=session))

    search = [p for u, p in session.calls if "search" in u]
    assert all(p["sort"] == "stars" for p in search)  # old code sent s=stars
    assert len(search) == 2
    assert len(rows) == 150
    assert rows[1]["sha"] == "abc123main" and rows[0]["sha"] == "abc123master"
    assert rows[0]["zip"].endswith("/zip/abc123master")
    assert session.headers["Authorization"] == "Bearer t"
    assert (tmp_path / "downloads" / "o__r0.zip").exists()
    assert len((tmp_path / "repos.csv").read_text().splitlines()) == 151


def test_crawl_is_resumable(tmp_path):
    gh = crawl.GitHub(session=FakeSession([_repo(1), _repo(2)]))
    crawl.crawl(tmp_path, "q", 10, gh=gh)
    session = FakeSession([_repo(1), _repo(2), _repo(3)])
    rows = crawl.crawl(tmp_path, "q", 10, gh=crawl.GitHub(session=session))
    assert len(rows) == 3
    assert sum("/commits/" in u for u, _ in session.calls) == 1


# ---------------------------------------------------------------- projects
def _zip_bytes(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in files.items():
            z.writestr(name, body)
    return buf.getvalue()


def test_bad_zip_does_not_reuse_previous_archive(tmp_path):
    dl = tmp_path / "downloads"
    dl.mkdir()
    (dl / "a.zip").write_bytes(_zip_bytes({"a-main/pom.xml": "<project/>"}))
    (dl / "b.zip").write_bytes(b"<html>404</html>")
    stats = projects.extract(dl, tmp_path / "repos")
    assert stats == {"extracted": 1, "already_extracted": 0, "bad": 1}
    assert not (tmp_path / "repos" / "b").exists()  # old code: copy of a
    assert (dl / "bad" / "b.zip").exists()


def test_maven_projects_picks_top_pom_at_any_depth(tmp_path):
    root = tmp_path / "x" / "y" / "z" / "repos"  # depth no longer matters
    for rel in [
        "p1/p1-main/pom.xml",
        "p1/p1-main/mod/pom.xml",
        "p2/p2-main/sub/pom.xml",
        "p3/p3-main/README",
    ]:
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("x")
    found = projects.maven_projects(root)
    assert found == [root / "p1/p1-main", root / "p2/p2-main/sub"]


# -------------------------------------------------------------------- scan
SCRIPT = (
    "import sys, pathlib; d = pathlib.Path(sys.argv[1]); "
    "(d / 'target/fortify').mkdir(parents=True, exist_ok=True); "
    "mode = sys.argv[2]; "
    "mode == 'ok' and (d / 'target/fortify' / 'r.fpr').write_text('fpr'); "
    "print('BUILD Failed' if mode == 'ok' else 'BUILD SUCCESS'); "
    "sys.exit(3 if mode == 'fail' else 0)"
)


def test_scan_status_uses_exit_code_and_fpr(tmp_path):
    script = tmp_path / "fake scan.py"
    script.write_text(SCRIPT.replace("; ", "\n"))
    projs = []
    for name in ("ok", "fail", "nofpr"):
        (tmp_path / name).mkdir()
        projs.append((name, tmp_path / name))
    template = f'"{sys.executable}" "{script}" {{project_dir}} {{name}}'
    results = {r["name"]: r for r in scan.scan_all(projs, template, tmp_path / "out")}

    # "ok" prints the word "Failed" but succeeded; old code keyed off that text.
    assert results["ok"]["status"] == "ok"
    assert (tmp_path / "out/fprs/ok.fpr").exists()
    assert results["fail"]["status"] == "failed" and results["fail"]["returncode"] == 3
    assert results["nofpr"]["status"] == "no_fpr"
    assert len((tmp_path / "out/scan_results.csv").read_text().splitlines()) == 4


def test_build_command_keeps_paths_with_spaces_whole(tmp_path):
    cmd = scan.build_command("sh run.sh {project_dir} {name}", tmp_path / "a b", "proj")
    assert cmd == ["sh", "run.sh", str(tmp_path / "a b"), "proj"]


# ----------------------------------------------------------------- metrics
def test_total_loc(tmp_path):
    for name, locs in {"p1": [10, 5], "p2": [7]}.items():
        d = tmp_path / name
        d.mkdir()
        (d / "class.csv").write_text("file,class,loc\n" + "".join(f"f,c,{n}\n" for n in locs))
    (tmp_path / "p3").mkdir()
    (tmp_path / "p3" / "class.csv").write_text("")
    assert metrics.total_loc(tmp_path) == {"p1": 15, "p2": 7, "p3": 0}


# --------------------------------------------------------------------- c2v
def test_c2v_paths_label_every_context(tmp_path):
    src = tmp_path / "x.c2v"
    src.write_text("get|name a,1,b c,2,d    \nset|x e,3,f\n\n")
    out = tmp_path / "out.txt"
    assert c2v.extract_paths(src, out) == 3
    assert out.read_text().splitlines() == ["get|name a,1,b", "get|name c,2,d", "set|x e,3,f"]
