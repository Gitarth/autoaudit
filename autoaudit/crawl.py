"""
Find Java repositories on GitHub and download them pinned to a commit.

Every download is recorded in <data>/repos.csv with the commit SHA, so the
corpus can be re-created exactly.
"""

from __future__ import annotations

import csv
import logging
import math
import os
import time
from pathlib import Path

import requests

log = logging.getLogger(__name__)

API = "https://api.github.com"
SEARCH_CAP = 1000  # GitHub search never returns more than 1000 results
MAX_PER_PAGE = 100
MANIFEST_FIELDS = ["full_name", "stars", "size_kb", "default_branch", "sha", "license", "zip"]
NO_LICENSE = "NOASSERTION"


class GitHub:
    def __init__(self, token: str | None = None, session: requests.Session | None = None):
        self.s = session or requests.Session()
        self.s.headers["Accept"] = "application/vnd.github+json"
        self.s.headers["X-GitHub-Api-Version"] = "2022-11-28"
        token = token or os.environ.get("GITHUB_TOKEN")
        if token:
            self.s.headers["Authorization"] = f"Bearer {token}"

    def get(
        self, url: str, params: dict | None = None, stream: bool = False, retries: int = 5
    ) -> requests.Response:
        for attempt in range(retries):
            res = self.s.get(url, params=params, stream=stream, timeout=60)
            if res.status_code in (403, 429) and res.headers.get("X-RateLimit-Remaining") == "0":
                reset = int(res.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(reset - time.time(), 1) + 1
                log.warning("Rate limited; sleeping %.0fs", wait)
                time.sleep(wait)
                continue
            if res.status_code >= 500 and attempt < retries - 1:
                time.sleep(2**attempt)
                continue
            res.raise_for_status()
            return res
        res.raise_for_status()
        return res

    def search_repos(self, query: str, limit: int, sort: str = "stars") -> list[dict]:
        limit = min(limit, SEARCH_CAP)
        params = {"q": query, "sort": sort, "order": "desc", "per_page": MAX_PER_PAGE}
        first = self.get(f"{API}/search/repositories", {**params, "page": 1}).json()
        total = min(first["total_count"], limit)
        if first.get("incomplete_results"):
            log.warning("GitHub reported incomplete search results")
        items = first["items"]
        for page in range(2, pages_needed(total) + 1):
            items += self.get(f"{API}/search/repositories", {**params, "page": page}).json()["items"]
        return items[:total]

    def head_sha(self, full_name: str, ref: str) -> str:
        return self.get(f"{API}/repos/{full_name}/commits/{ref}").json()["sha"]


def pages_needed(count: int, per_page: int = MAX_PER_PAGE) -> int:
    return math.ceil(min(count, SEARCH_CAP) / per_page)


def zip_url(full_name: str, sha: str) -> str:
    return f"https://codeload.github.com/{full_name}/zip/{sha}"


def safe_name(full_name: str) -> str:
    return full_name.replace("/", "__")


def download(gh: GitHub, url: str, dest: Path) -> None:
    tmp = dest.with_suffix(".part")
    with gh.get(url, stream=True) as res, open(tmp, "wb") as fh:
        for chunk in res.iter_content(chunk_size=1 << 16):
            fh.write(chunk)
    tmp.replace(dest)


def license_of(repo: dict) -> str:
    """SPDX id GitHub detected for the repo, or NOASSERTION (none/unrecognised)."""
    lic = repo.get("license") or {}
    spdx = lic.get("spdx_id")
    return spdx if spdx and spdx != "NOASSERTION" else NO_LICENSE


def crawl(
    data_dir: Path,
    query: str,
    limit: int,
    min_size_kb: int = 100,
    gh: GitHub | None = None,
    allow_licenses: set[str] | None = None,
) -> list[dict]:
    """Download matching repos. Every repo's license is recorded; if
    `allow_licenses` is given, repos under any other license are skipped."""
    gh = gh or GitHub()
    zips = data_dir / "downloads"
    zips.mkdir(parents=True, exist_ok=True)
    manifest_path = data_dir / "repos.csv"

    done: dict[str, dict] = {}
    if manifest_path.exists():
        with open(manifest_path, newline="") as fh:
            done = {r["full_name"]: r for r in csv.DictReader(fh)}

    repos = gh.search_repos(query, limit)
    log.info("Search returned %d repositories", len(repos))
    rows = list(done.values())
    for repo in repos:
        name = repo["full_name"]
        if name in done or repo.get("fork"):  # forks duplicate code across projects
            continue
        if repo["size"] < min_size_kb:
            continue
        lic = license_of(repo)
        if allow_licenses is not None and lic not in allow_licenses:
            log.info("Skipping %s: license %s not allowed", name, lic)
            continue
        try:
            sha = gh.head_sha(name, repo["default_branch"])
            url = zip_url(name, sha)
            download(gh, url, zips / f"{safe_name(name)}.zip")
        except requests.HTTPError as err:
            log.warning("Skipping %s: %s", name, err)
            continue
        row = {
            "full_name": name,
            "stars": repo["stargazers_count"],
            "size_kb": repo["size"],
            "default_branch": repo["default_branch"],
            "sha": sha,
            "license": lic,
            "zip": url,
        }
        rows.append(row)
        done[name] = row
        log.info("Downloaded %s @ %s", name, sha[:10])
        _write_manifest(manifest_path, rows)  # incremental: resumable after a crash
    _write_manifest(manifest_path, rows)
    return rows


def _write_manifest(path: Path, rows: list[dict]) -> None:
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=MANIFEST_FIELDS, restval="")
        w.writeheader()
        w.writerows(rows)
    tmp.replace(path)
