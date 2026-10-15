"""
Mine candidate training cases from OSV (https://osv.dev) advisory dumps.

An OSV ecosystem dump (`https://osv-vulnerabilities.storage.googleapis.com/
<Ecosystem>/all.zip`) holds one JSON record per advisory. A record becomes a
candidate case when:

- its CWEs include one autoaudit has rules for (injection-style taint flows);
- it names exactly one GitHub fix commit (a `.../commit/<sha>` reference, or a
  GIT range's `fixed` event), so the fix diff is the ground truth;
- it is not a malware report (`MAL-...`).

At most `per_repo` cases are kept per repository so one project cannot
dominate. The output is a corpus file `bench` and `corpus-mine` read.
"""

from __future__ import annotations

import json
import re
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

ECOSYSTEM_LANGUAGE = {
    "PyPI": "python",
    "npm": "javascript",
    "Go": "go",
    "Packagist": "php",
    "NuGet": "csharp",
    "Maven": "java",
}
# advisory CWE -> the CWE our rules report
CWE_MAP = {
    "CWE-89": "CWE-89",
    "CWE-564": "CWE-89",
    "CWE-78": "CWE-78",
    "CWE-77": "CWE-78",
    "CWE-88": "CWE-78",
    "CWE-22": "CWE-22",
    "CWE-23": "CWE-22",
    "CWE-35": "CWE-22",
    "CWE-36": "CWE-22",
    "CWE-73": "CWE-22",
    "CWE-98": "CWE-22",
    "CWE-79": "CWE-79",
    "CWE-80": "CWE-79",
    "CWE-83": "CWE-79",
    "CWE-87": "CWE-79",
    "CWE-94": "CWE-94",
    "CWE-95": "CWE-94",
    "CWE-1336": "CWE-94",
    "CWE-917": "CWE-917",
    "CWE-611": "CWE-611",
    "CWE-776": "CWE-611",
    "CWE-918": "CWE-918",
    "CWE-502": "CWE-502",
    "CWE-90": "CWE-90",
    "CWE-643": "CWE-643",
}
_COMMIT = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+)/commit/([0-9a-f]{40})(?:[/#?].*)?$")
_REPO = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


def fix_commits(rec: dict) -> set[tuple[str, str]]:
    """{(repo url, sha)} of the fix commits a record names."""
    out = set()
    for ref in rec.get("references", []):
        m = _COMMIT.match(ref.get("url", ""))
        if m:
            out.add((f"https://github.com/{m.group(1)}/{m.group(2)}", m.group(3)))
    for aff in rec.get("affected", []):
        for rng in aff.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            m = _REPO.match(rng.get("repo", ""))
            if not m:
                continue
            repo = f"https://github.com/{m.group(1)}/{m.group(2)}"
            for ev in rng.get("events", []):
                sha = ev.get("fixed", "")
                if re.fullmatch(r"[0-9a-f]{40}", sha):
                    out.add((repo, sha))
    return {(r.lower(), s) for r, s in out}


def cwes(rec: dict) -> list[str]:
    ids = (rec.get("database_specific") or {}).get("cwe_ids") or []
    return [c.upper() for c in ids if isinstance(c, str)]


def _name(repo: str, sha: str) -> str:
    owner, name = repo.rstrip("/").split("/")[-2:]
    return re.sub(r"[^A-Za-z0-9_-]", "-", f"{owner}__{name}__{sha[:8]}")


def candidates(dumps: list[Path], per_repo: int = 2, exclude_repos: set[str] = frozenset()) -> dict:
    """Corpus document ({"description", "cases"}) from OSV ecosystem zips."""
    seen: dict[tuple[str, str], dict] = {}
    stats: Counter = Counter()
    for dump in dumps:
        language = ECOSYSTEM_LANGUAGE.get(dump.stem)
        with zipfile.ZipFile(dump) as z:
            for entry in z.namelist():
                if not entry.endswith(".json") or entry.startswith("MAL-"):
                    continue
                rec = json.loads(z.read(entry))
                if rec.get("withdrawn"):
                    stats["withdrawn"] += 1
                    continue
                mapped = sorted({CWE_MAP[c] for c in cwes(rec) if c in CWE_MAP})
                if not mapped:
                    stats["other_cwe"] += 1
                    continue
                commits = fix_commits(rec)
                if len(commits) != 1:
                    stats["no_single_fix_commit"] += 1
                    continue
                (repo, sha) = commits.pop()
                if repo in exclude_repos:
                    stats["excluded_repo"] += 1
                    continue
                key = (repo, sha)
                aliases = [a for a in rec.get("aliases", []) if a.startswith("CVE-")]
                if key in seen:  # the same fix published under several ids
                    stats["duplicate"] += 1
                    continue
                seen[key] = {
                    "name": _name(repo, sha),
                    "language": language,
                    "repo": repo,
                    "fix": sha,
                    "id": aliases[0] if aliases else rec.get("id"),
                    "cwe": mapped[0],
                    "summary": (rec.get("summary") or rec.get("details") or "")[:300],
                    "advisory": f"https://osv.dev/vulnerability/{rec.get('id')}",
                    "published": rec.get("published"),
                }
                stats[f"kept:{language}"] += 1
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for c in sorted(seen.values(), key=lambda c: c.get("published") or "", reverse=True):
        by_repo[c["repo"]].append(c)
    cases = [c for cs in by_repo.values() for c in cs[:per_repo]]
    stats["cases"] = len(cases)
    stats["repositories"] = len(by_repo)
    return {
        "description": "Candidate cases mined from OSV advisories (one GitHub fix commit, a CWE "
        "autoaudit has rules for). Unverified until `corpus-mine` fetches each fix.",
        "stats": dict(stats),
        "cases": cases,
    }
