"""Builds a labeled benchmark of PR-sized diffs.

Positives come from real CVE fix commits, read backwards: reversing a fix produces a diff that
*introduces* the vulnerability, which is what a reviewer would actually be handed. Negatives are
ordinary commits from the same repositories, so the two classes differ in content and not in style.

Network access is confined to fetch_* functions; everything the tests care about is pure.
"""

import argparse
import hashlib
import json
import os
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
    split: str = ""


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


COMMIT_URL = re.compile(r"^https://github\.com/([^/]+/[^/]+)/commit/([0-9a-fA-F]{7,40})")


def fix_commits_from_references(vuln: dict) -> list[dict]:
    """Patch commits linked from an advisory's references.

    npm advisories in OSV carry no GIT ranges at all; their fixes live only as commit URLs among
    the references. These also tend to be the actual patch, where a GIT range's "fixed" event is
    often a release commit that only bumps a version string."""
    cve_id = next((a for a in vuln.get("aliases", []) if a.startswith("CVE-")), None)
    found = []
    for ref in vuln.get("references", []):
        if match := COMMIT_URL.match(ref.get("url", "")):
            found.append(
                {
                    "id": vuln.get("id"),
                    "cve_id": cve_id,
                    "repo": match.group(1),
                    "commit": match.group(2),
                    "category": (vuln.get("summary") or "")[:80],
                }
            )
    return found


def split_for(example_id: str) -> str:
    """Stable half/half split by id hash. Tuning happens on dev only; the reported number comes
    from test, which no prompt change was ever checked against."""
    digest = hashlib.sha256(example_id.encode()).digest()
    return "test" if digest[0] % 2 else "dev"


def select_candidates(candidates: list[dict]) -> list[dict]:
    """One example per advisory, newest first, rotating between repos.

    Without the per-advisory dedup, one CVE with several fix commits fills the whole positive
    class — and since the diff file is named after the advisory, the copies overwrite each other.
    """
    unique: dict[str, dict] = {}
    for candidate in candidates:
        key = candidate.get("id") or candidate.get("commit")
        if key and key not in unique:
            unique[key] = candidate

    ordered = sorted(unique.values(), key=lambda c: (-_year(c), c.get("repo", "")))

    by_repo: dict[str, list[dict]] = {}
    for candidate in ordered:
        by_repo.setdefault(candidate.get("repo", ""), []).append(candidate)

    interleaved = []
    while any(by_repo.values()):
        for queue in by_repo.values():
            if queue:
                interleaved.append(queue.pop(0))
    return interleaved


def _year(candidate: dict) -> int:
    for field in ("cve_id", "id"):
        if match := re.search(r"(19|20)\d{2}", str(candidate.get(field) or "")):
            return int(match.group(0))
    return 0


def _strip_prefix(path: str) -> str:
    return path[2:] if path.startswith(("a/", "b/")) else path


TEST_PATH = re.compile(r"(^|/)tests?/|(^|/)test_|_test\.", re.IGNORECASE)
DOC_PATH = re.compile(r"(^|/)docs?/|\.(rst|md|txt|cfg|ini|toml|po)$", re.IGNORECASE)
VERSION_PATH = re.compile(r"(^|/)_?version\.py$|(^|/)setup\.py$", re.IGNORECASE)


def filter_to_source(diff_text: str) -> str:
    """Keeps only production source files.

    Positives are reversed fix commits, so their docs and test hunks read as "this PR deletes a
    security regression test and a release note naming a CVE" — a giveaway that has nothing to do
    with reviewing the code. Negatives get the same treatment so the two classes stay comparable.
    """
    sections = re.split(r"(?m)^(?=diff --git )", diff_text)
    kept = [section for section in sections if section.strip() and _is_source_section(section)]
    return "".join(kept)


def _is_source_section(section: str) -> bool:
    paths = [
        line[4:].strip()
        for line in section.splitlines()
        if line.startswith("+++ ") or line.startswith("--- ")
    ]
    paths = [_strip_prefix(p) for p in paths if p != "/dev/null"]
    if not paths:
        return False
    return any(
        path.endswith(SUPPORTED_SUFFIXES)
        and not TEST_PATH.search(path)
        and not DOC_PATH.search(path)
        and not VERSION_PATH.search(path)
        for path in paths
    )


def is_reviewable_diff(diff_text: str) -> bool:
    if not diff_text.strip():
        return False
    lines = diff_text.splitlines()
    if len(lines) > MAX_DIFF_LINES:
        return False
    touched = [line for line in lines if line.startswith("+++ ") or line.startswith("--- ")]
    return any(path.endswith(SUPPORTED_SUFFIXES) for path in touched)


def validate_manifest(entries: list[ManifestEntry], minimum: int = 0) -> None:
    if len(entries) < minimum:
        raise ValueError(
            f"only {len(entries)} examples, expected at least {minimum}. A truncated benchmark "
            "reads as a result but is not one — usually this means the build was rate limited."
        )

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

    for split in {e.split for e in entries if e.split}:
        in_split = [e for e in entries if e.split == split]
        pos = sum(1 for e in in_split if e.is_vulnerable)
        if pos != len(in_split) - pos:
            raise ValueError(
                f"{split} split balance is off: {pos} vulnerable vs {len(in_split) - pos} benign"
            )


def write_manifest(entries: list[ManifestEntry], path: Path, minimum: int = 0) -> None:
    validate_manifest(entries, minimum=minimum)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([asdict(e) for e in entries], indent=2), encoding="utf-8")


# --- network ---------------------------------------------------------------


class RateLimited(RuntimeError):
    """Raised loudly: a rate-limited build silently produces a toy dataset otherwise."""


def _github_token() -> str | None:
    if token := os.environ.get("GITHUB_TOKEN"):
        return token
    env_file = Path(__file__).resolve().parents[1] / ".env"
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            name, _, value = line.partition("=")
            if name.strip() == "GITHUB_TOKEN" and value.strip():
                return value.strip().strip("\"'")
    return None


def _get(url: str, accept: str = "application/json") -> str:
    headers = {"Accept": accept, "User-Agent": "ai-pr-guardian"}
    if token := _github_token():
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        if error.code in (403, 429) and error.headers.get("X-RateLimit-Remaining") == "0":
            reset = int(error.headers.get("X-RateLimit-Reset", 0))
            minutes = max(0, int((reset - time.time()) / 60))
            raise RateLimited(
                f"GitHub rate limit exhausted; resets in ~{minutes} min. "
                "Re-run to resume (downloaded diffs are cached), or set GITHUB_TOKEN in .env "
                "for 5000 requests/hour."
            ) from error
        raise


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
        found.extend(fix_commits_from_references(vuln))
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
        return None  # commit genuinely unreachable; RateLimited is not caught here


def fetch_recent_commits(repo: str, limit: int = 30) -> list[str]:
    try:
        raw = _get(f"{GITHUB_API}/repos/{repo}/commits?per_page={limit}")
    except (urllib.error.HTTPError, urllib.error.URLError):
        return []  # repo gone or renamed; RateLimited is not caught here
    return [c["sha"] for c in json.loads(raw)]


# --- assembly --------------------------------------------------------------


def _load_existing(out_dir: Path) -> list[ManifestEntry]:
    manifest = out_dir / "manifest.json"
    if not manifest.is_file():
        return []
    entries = [ManifestEntry(**row) for row in json.loads(manifest.read_text(encoding="utf-8"))]
    return [e for e in entries if Path(e.diff_path).is_file()]


def build(packages: list[tuple[str, str]], target_per_class: int, out_dir: Path) -> list[ManifestEntry]:
    diffs_dir = out_dir / "diffs"
    diffs_dir.mkdir(parents=True, exist_ok=True)

    # Resume: a rate-limited run is expected, so keep whatever earlier runs already downloaded.
    existing = _load_existing(out_dir)
    positives = [e for e in existing if e.is_vulnerable]
    known_ids = {e.id for e in existing}
    fix_shas: set[str] = {e.commit for e in existing}
    repos_seen: list[str] = [e.repo for e in positives]
    if existing:
        print(f"resuming from {len(positives)} positives, {len(existing) - len(positives)} negatives")

    candidates = []
    for ecosystem, package in packages:
        candidates.extend(fetch_fix_commits(ecosystem, package))
    print(f"{len(candidates)} fix commits from OSV; deduplicating by advisory")

    for fix in select_candidates(candidates):
        if len(positives) >= target_per_class:
            break
        if not fix["repo"] or fix["commit"] in fix_shas or fix["id"] in known_ids:
            continue
        diff = fetch_commit_diff(fix["repo"], fix["commit"])
        time.sleep(1)  # unauthenticated GitHub allows 60 requests/hour
        if not diff:
            continue
        diff = filter_to_source(diff)
        if not is_reviewable_diff(diff):
            continue  # release commits and docs-only fixes carry no vulnerability to find

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
                split=split_for(fix["id"]),
            )
        )
        print(f"  + positive {fix['id']} ({fix['repo']})")

    # One benign example per positive, from the SAME repo. Without this the negatives all come
    # from whichever repo is listed first, and the classifier can separate the classes by
    # project style instead of by whether the code is vulnerable.
    negatives: list[ManifestEntry] = [e for e in existing if not e.is_vulnerable]
    covered_repos = {e.repo for e in negatives}
    for repo in [r for r in repos_seen if r not in covered_repos]:
        if len(negatives) >= len(positives):
            break
        for sha in fetch_recent_commits(repo):
            if sha in fix_shas or any(n.commit == sha for n in negatives):
                continue
            diff = fetch_commit_diff(repo, sha)
            time.sleep(1)
            if not diff:
                continue
            diff = filter_to_source(diff)
            if not is_reviewable_diff(diff):
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
                    # Inherit the paired positive's half so dev and test each stay balanced.
                    split=positives[len(negatives)].split,
                )
            )
            print(f"  - negative {sha[:10]} ({repo})")
            break  # one per repo, then move on to match the next positive

    entries = positives[: len(negatives)] + negatives
    random.shuffle(entries)
    return entries


DEFAULT_PACKAGES = [
    ("PyPI", p)
    for p in (
        "django", "flask", "requests", "pillow", "aiohttp", "jinja2", "werkzeug", "urllib3",
        "tornado", "twisted", "pyyaml", "sqlalchemy", "cryptography", "paramiko", "scrapy",
        "gunicorn", "starlette", "fastapi", "mlflow", "ansible", "salt", "bleach", "lxml",
    )
] + [
    ("npm", p)
    for p in (
        "express", "axios", "lodash", "jsonwebtoken", "minimist", "node-fetch", "ws", "next",
        "undici", "tar", "handlebars", "ejs", "marked", "sanitize-html", "xml2js", "moment",
        "semver", "qs", "follow-redirects", "socket.io", "mongoose", "sequelize", "vm2",
    )
]


def main() -> None:
    parser = argparse.ArgumentParser(description="build the labeled benchmark dataset")
    parser.add_argument("--per-class", type=int, default=25, help="target examples per class")
    parser.add_argument("--out", default="benchmark/dataset", help="output directory")
    parser.add_argument(
        "--minimum", type=int, default=0, help="fail if fewer than this many examples were built"
    )
    args = parser.parse_args()

    out_dir = Path(args.out)
    try:
        entries = build(DEFAULT_PACKAGES, args.per_class, out_dir)
    except RateLimited as limit:
        print(f"\n{limit}")
        raise SystemExit(2) from limit

    write_manifest(entries, out_dir / "manifest.json", minimum=args.minimum)
    print(f"\nwrote {len(entries)} examples to {out_dir / 'manifest.json'}")


if __name__ == "__main__":
    main()
