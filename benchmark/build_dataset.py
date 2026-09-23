"""Builds a labeled benchmark of PR-sized diffs.

Positives come from real CVE fix commits, read backwards: reversing a fix produces a diff that
*introduces* the vulnerability, which is what a reviewer would actually be handed. Negatives are
ordinary commits from the same repositories, so the two classes differ in content and not in style.

Network access is confined to fetch_* functions; everything the tests care about is pure.
"""

import argparse
import json
import random
import re
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
GITHUB_API = "https://api.github.com"

SUPPORTED_SUFFIXES = (".py", ".js", ".ts", ".jsx", ".tsx")
MAX_DIFF_LINES = 200
HUNK_HEADER = re.compile(r"^@@ -(\d+)(,\d+)? \+(\d+)(,\d+)? @@(.*)$")


@dataclass
class ManifestEntry:
    id: str
    repo: str
    commit: str
    diff_path: str
    is_vulnerable: bool | None
    cve_id: str | None
    category: str | None


def reverse_diff(diff_text: str) -> str:
    out = []
    pending_old_path: str | None = None

    for line in diff_text.splitlines(keepends=True):
        stripped = line.rstrip("\n")
        if stripped.startswith("--- "):
            # Hold it: the two header paths swap places, so we need its partner first.
            pending_old_path = stripped[4:]
        elif stripped.startswith("+++ ") and pending_old_path is not None:
            # The paths swap sides, but the a/ and b/ prefixes belong to the sides, not the
            # paths — so for an ordinary edit the header comes out unchanged, and only a
            # rename actually flips.
            ending = "\n" if line.endswith("\n") else ""
            out.append(f"--- a/{_strip_prefix(stripped[4:])}{ending}")
            out.append(f"+++ b/{_strip_prefix(pending_old_path)}{ending}")
            pending_old_path = None
        elif match := HUNK_HEADER.match(stripped):
            old_start, old_len, new_start, new_len, tail = match.groups()
            ending = "\n" if line.endswith("\n") else ""
            out.append(f"@@ -{new_start}{new_len or ''} +{old_start}{old_len or ''} @@{tail}{ending}")
        elif stripped.startswith("+"):
            out.append("-" + line[1:])
        elif stripped.startswith("-"):
            out.append("+" + line[1:])
        else:
            out.append(line)
    return "".join(out)


def _strip_prefix(path: str) -> str:
    return path[2:] if path.startswith(("a/", "b/")) else path


def is_reviewable_diff(diff_text: str) -> bool:
    lines = diff_text.splitlines()
    if len(lines) > MAX_DIFF_LINES:
        return False
    touched = [line for line in lines if line.startswith("+++ ") or line.startswith("--- ")]
    return any(path.endswith(SUPPORTED_SUFFIXES) for path in touched)


def validate_manifest(entries: list[ManifestEntry]) -> None:
    for entry in entries:
        if entry.is_vulnerable is None:
            raise ValueError(f"{entry.id}: is_vulnerable is unset; an unlabeled example is useless")

    positives = sum(1 for e in entries if e.is_vulnerable)
    negatives = len(entries) - positives
    if positives != negatives:
        raise ValueError(
            f"dataset balance is off: {positives} vulnerable vs {negatives} benign. "
            "Unbalanced classes make the false-positive rate unreadable."
        )


def write_manifest(entries: list[ManifestEntry], path: Path) -> None:
    validate_manifest(entries)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([asdict(e) for e in entries], indent=2), encoding="utf-8")


# --- network ---------------------------------------------------------------


def _get(url: str, accept: str = "application/json") -> str:
    request = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "ai-pr-guardian"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8", errors="replace")


def fetch_fix_commits(ecosystem: str, package: str) -> list[dict]:
    """Ask OSV which commits fixed known vulnerabilities in a package."""
    payload = json.dumps({"package": {"name": package, "ecosystem": ecosystem}}).encode()
    request = urllib.request.Request(
        OSV_QUERY_URL, data=payload, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        vulns = json.loads(response.read().decode()).get("vulns", [])

    found = []
    for vuln in vulns:
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                if rng.get("type") != "GIT":
                    continue
                repo = rng.get("repo", "").removeprefix("https://github.com/").removesuffix(".git")
                for event in rng.get("events", []):
                    if sha := event.get("fixed"):
                        found.append(
                            {
                                "id": vuln.get("id"),
                                "cve_id": next(
                                    (a for a in vuln.get("aliases", []) if a.startswith("CVE-")), None
                                ),
                                "repo": repo,
                                "commit": sha,
                                "category": (vuln.get("summary") or "")[:80],
                            }
                        )
    return found


def fetch_commit_diff(repo: str, sha: str) -> str | None:
    try:
        return _get(f"{GITHUB_API}/repos/{repo}/commits/{sha}", accept="application/vnd.github.diff")
    except (urllib.error.HTTPError, urllib.error.URLError):
        return None


def fetch_recent_commits(repo: str, limit: int = 30) -> list[str]:
    try:
        raw = _get(f"{GITHUB_API}/repos/{repo}/commits?per_page={limit}")
    except (urllib.error.HTTPError, urllib.error.URLError):
        return []
    return [c["sha"] for c in json.loads(raw)]


# --- assembly --------------------------------------------------------------


def build(packages: list[tuple[str, str]], target_per_class: int, out_dir: Path) -> list[ManifestEntry]:
    diffs_dir = out_dir / "diffs"
    diffs_dir.mkdir(parents=True, exist_ok=True)

    positives: list[ManifestEntry] = []
    fix_shas: set[str] = set()
    repos_seen: list[str] = []

    for ecosystem, package in packages:
        if len(positives) >= target_per_class:
            break
        for fix in fetch_fix_commits(ecosystem, package):
            if len(positives) >= target_per_class:
                break
            if not fix["repo"] or fix["commit"] in fix_shas:
                continue
            diff = fetch_commit_diff(fix["repo"], fix["commit"])
            time.sleep(1)  # unauthenticated GitHub allows 60 requests/hour
            if not diff or not is_reviewable_diff(diff):
                continue

            fix_shas.add(fix["commit"])
            repos_seen.append(fix["repo"])
            name = f"{fix['id']}.diff"
            (diffs_dir / name).write_text(reverse_diff(diff), encoding="utf-8")
            positives.append(
                ManifestEntry(
                    id=fix["id"],
                    repo=fix["repo"],
                    commit=fix["commit"],
                    diff_path=str((diffs_dir / name).as_posix()),
                    is_vulnerable=True,
                    cve_id=fix["cve_id"],
                    category=fix["category"],
                )
            )
            print(f"  + positive {fix['id']} ({fix['repo']})")

    negatives: list[ManifestEntry] = []
    for repo in _cycle_unique(repos_seen):
        if len(negatives) >= len(positives):
            break
        for sha in fetch_recent_commits(repo):
            if len(negatives) >= len(positives):
                break
            if sha in fix_shas:
                continue
            diff = fetch_commit_diff(repo, sha)
            time.sleep(1)
            if not diff or not is_reviewable_diff(diff):
                continue

            name = f"benign-{sha[:10]}.diff"
            (diffs_dir / name).write_text(diff, encoding="utf-8")
            negatives.append(
                ManifestEntry(
                    id=f"benign-{sha[:10]}",
                    repo=repo,
                    commit=sha,
                    diff_path=str((diffs_dir / name).as_posix()),
                    is_vulnerable=False,
                    cve_id=None,
                    category=None,
                )
            )
            print(f"  - negative {sha[:10]} ({repo})")

    entries = positives[: len(negatives)] + negatives
    random.shuffle(entries)
    return entries


def _cycle_unique(items: list[str]) -> list[str]:
    seen, unique = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


DEFAULT_PACKAGES = [
    ("PyPI", "django"),
    ("PyPI", "flask"),
    ("PyPI", "requests"),
    ("PyPI", "pillow"),
    ("PyPI", "aiohttp"),
    ("npm", "express"),
    ("npm", "axios"),
    ("npm", "lodash"),
]


def main() -> None:
    parser = argparse.ArgumentParser(description="build the labeled benchmark dataset")
    parser.add_argument("--per-class", type=int, default=25, help="target examples per class")
    parser.add_argument("--out", default="benchmark/dataset", help="output directory")
    args = parser.parse_args()

    out_dir = Path(args.out)
    entries = build(DEFAULT_PACKAGES, args.per_class, out_dir)
    write_manifest(entries, out_dir / "manifest.json")
    print(f"\nwrote {len(entries)} examples to {out_dir / 'manifest.json'}")


if __name__ == "__main__":
    main()
