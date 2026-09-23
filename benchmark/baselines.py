"""The bar the multi-agent pipeline has to clear.

Semgrep is given the complete post-change file — the setting its rules are written for — while the
agents see only the diff. That handicaps the pipeline, not the baseline, which is the right
direction for an honest comparison: beating a baseline you crippled proves nothing.

An earlier version scanned only the added lines, written to a temp file. Those fragments are not
parseable Python, so Semgrep matched nothing anywhere and scored a meaningless 0.00 across the
board (benchmark/results/baseline-run-01.json).
"""

import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from guardian.diff_parser import parse_diff
from guardian.models import Decision
from guardian.tools.semgrep_runner import run_semgrep

RAW_CONTENT = "https://raw.githubusercontent.com"
SCANNABLE_SUFFIXES = (".py", ".js", ".ts", ".jsx", ".tsx")


def changed_source_paths(diff_text: str) -> list[str]:
    return [f.path for f in parse_diff(diff_text).files if f.path.endswith(SCANNABLE_SUFFIXES)]


def fetch_file_at(repo: str, ref: str, path: str, cache_dir: Path) -> str | None:
    """Files come from raw.githubusercontent.com, which is not subject to the API rate limit."""
    cached = cache_dir / ref[:12] / path
    if cached.is_file():
        return cached.read_text(encoding="utf-8", errors="replace")

    try:
        with urllib.request.urlopen(f"{RAW_CONTENT}/{repo}/{ref}/{path}", timeout=30) as response:
            content = response.read().decode("utf-8", errors="replace")
    except (urllib.error.HTTPError, urllib.error.URLError):
        return None

    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_text(content, encoding="utf-8")
    return content


def semgrep_baseline_at(
    repo: str,
    ref: str,
    diff_text: str,
    cache_dir: Path,
    runner=run_semgrep,
    fetcher=fetch_file_at,
) -> tuple[Decision, int]:
    """Scans the post-change version of every source file the diff touches."""
    contents = {}
    for path in changed_source_paths(diff_text):
        if content := fetcher(repo, ref, path, cache_dir):
            contents[path] = content

    if not contents:
        return "approve", 0

    with tempfile.TemporaryDirectory() as tmp:
        names = []
        for path, content in contents.items():
            # Flattened into one directory: Semgrep's rules are per-file, and keeping the tree
            # would mean recreating package layouts we do not have.
            target = Path(tmp) / Path(path).name
            target.write_text(content, encoding="utf-8")
            names.append(target.name)
        findings = runner(tmp, names)

    return ("request_changes" if findings else "approve"), len(findings)
