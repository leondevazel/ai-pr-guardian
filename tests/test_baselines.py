from pathlib import Path

from benchmark.baselines import changed_source_paths, fetch_file_at, semgrep_baseline_at
from guardian.models import ToolFinding

DIFF = """diff --git a/src/app/db.py b/src/app/db.py
--- a/src/app/db.py
+++ b/src/app/db.py
@@ -1 +1 @@
-safe()
+unsafe()
diff --git a/docs/notes.rst b/docs/notes.rst
--- a/docs/notes.rst
+++ b/docs/notes.rst
@@ -1 +1 @@
-a
+b
"""


def fake_fetcher(repo, ref, path, cache_dir):
    return "import os\nos.system('ls ' + user_input)\n"


def test_only_scannable_source_paths_are_collected():
    assert changed_source_paths(DIFF) == ["src/app/db.py"]


def test_flags_when_semgrep_reports_a_finding():
    def runner(repo_path, files):
        return [ToolFinding(files[0], 2, "rule.x", "command injection", "block")]

    decision, count = semgrep_baseline_at(
        "acme/app", "sha", DIFF, Path("unused"), runner=runner, fetcher=fake_fetcher
    )
    assert (decision, count) == ("request_changes", 1)


def test_approves_when_semgrep_is_silent():
    decision, count = semgrep_baseline_at(
        "acme/app", "sha", DIFF, Path("unused"), runner=lambda *_: [], fetcher=fake_fetcher
    )
    assert (decision, count) == ("approve", 0)


def test_scans_whole_file_not_just_added_lines():
    """The regression that produced a 0.00 baseline: fragments do not parse."""
    seen = {}

    def runner(repo_path, files):
        seen["content"] = (Path(repo_path) / files[0]).read_text(encoding="utf-8")
        return []

    semgrep_baseline_at("acme/app", "sha", DIFF, Path("unused"), runner=runner, fetcher=fake_fetcher)
    assert seen["content"].startswith("import os")


def test_unfetchable_file_yields_approve_rather_than_crashing():
    decision, count = semgrep_baseline_at(
        "acme/app", "sha", DIFF, Path("unused"), runner=lambda *_: [], fetcher=lambda *a: None
    )
    assert (decision, count) == ("approve", 0)


def test_cached_file_is_read_from_disk_without_network(tmp_path):
    cached = tmp_path / "abcdef123456" / "src/app/db.py"
    cached.parent.mkdir(parents=True)
    cached.write_text("cached content", encoding="utf-8")

    assert fetch_file_at("acme/app", "abcdef123456", "src/app/db.py", tmp_path) == "cached content"
