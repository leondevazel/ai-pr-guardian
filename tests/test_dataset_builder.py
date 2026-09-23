import json

import pytest

from benchmark.build_dataset import (
    ManifestEntry,
    filter_to_source,
    is_reviewable_diff,
    reverse_diff,
    select_candidates,
    validate_manifest,
    write_manifest,
)

FIX_DIFF = """diff --git a/app/db.py b/app/db.py
index 1111111..2222222 100644
--- a/app/db.py
+++ b/app/db.py
@@ -10,3 +10,3 @@ import sqlite3
 def get_user(conn, user_id):
-    query = f"SELECT * FROM users WHERE id = {user_id}"
-    return conn.execute(query).fetchone()
+    query = "SELECT * FROM users WHERE id = ?"
+    return conn.execute(query, (user_id,)).fetchone()
"""


def entry(**overrides):
    base = {
        "id": "CVE-2024-0001",
        "repo": "acme/app",
        "commit": "abc123",
        "diff_path": "benchmark/dataset/diffs/CVE-2024-0001.diff",
        "is_vulnerable": True,
        "cve_id": "CVE-2024-0001",
        "category": "sql-injection",
    }
    base.update(overrides)
    return ManifestEntry(**base)


# --- reverse_diff: a fix commit read backwards is a PR that introduces the bug ---


def test_reversed_diff_adds_back_the_vulnerable_line():
    reversed_text = reverse_diff(FIX_DIFF)
    assert '+    query = f"SELECT * FROM users WHERE id = {user_id}"' in reversed_text


def test_reversed_diff_removes_the_fixed_line():
    reversed_text = reverse_diff(FIX_DIFF)
    assert '-    query = "SELECT * FROM users WHERE id = ?"' in reversed_text


def test_reversed_diff_swaps_file_headers_not_content():
    reversed_text = reverse_diff(FIX_DIFF)
    assert "--- a/app/db.py" in reversed_text
    assert "+++ b/app/db.py" in reversed_text


def test_reversed_diff_swaps_hunk_ranges():
    reversed_text = reverse_diff("@@ -10,3 +10,5 @@ ctx\n-old\n+new\n")
    assert reversed_text.splitlines()[0] == "@@ -10,5 +10,3 @@ ctx"


def test_reversing_twice_is_identity():
    assert reverse_diff(reverse_diff(FIX_DIFF)) == FIX_DIFF


def test_context_lines_are_untouched():
    assert " def get_user(conn, user_id):" in reverse_diff(FIX_DIFF)


# --- scope filter: keep diffs a reviewer could plausibly read ---


def test_rejects_diff_touching_no_supported_language():
    diff = "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-a\n+b\n"
    assert not is_reviewable_diff(diff)


def test_accepts_small_python_diff():
    assert is_reviewable_diff(FIX_DIFF)


def test_rejects_oversized_diff():
    huge = FIX_DIFF + "".join(f"+line {i}\n" for i in range(500))
    assert not is_reviewable_diff(huge)


# --- source filter: the label must not leak through docs or deleted tests ---

MIXED_DIFF = """diff --git a/src/app/auth.py b/src/app/auth.py
--- a/src/app/auth.py
+++ b/src/app/auth.py
@@ -1,2 +1,2 @@
-    if verify(token):
+    if token:
diff --git a/tests/test_auth.py b/tests/test_auth.py
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -1,2 +1,1 @@
-def test_rejects_forged_token():
-    assert not verify("forged")
diff --git a/docs/releases/2.1.txt b/docs/releases/2.1.txt
--- a/docs/releases/2.1.txt
+++ b/docs/releases/2.1.txt
@@ -1,2 +1,1 @@
-Fixed an authentication bypass (CVE-2024-1234).
"""


def test_keeps_source_files():
    filtered = filter_to_source(MIXED_DIFF)
    assert "src/app/auth.py" in filtered
    assert "+    if token:" in filtered


def test_drops_test_files_so_deleted_tests_do_not_give_the_answer_away():
    assert "tests/test_auth.py" not in filter_to_source(MIXED_DIFF)


def test_drops_release_notes_naming_the_cve():
    filtered = filter_to_source(MIXED_DIFF)
    assert "CVE-2024-1234" not in filtered
    assert "docs/releases" not in filtered


def test_returns_empty_when_only_metadata_changed():
    version_bump = """diff --git a/src/PIL/_version.py b/src/PIL/_version.py
--- a/src/PIL/_version.py
+++ b/src/PIL/_version.py
@@ -1,1 +1,1 @@
-__version__ = "11.3.0"
+__version__ = "11.3.0.dev0"
"""
    assert filter_to_source(version_bump) == ""


def test_empty_filtered_diff_is_not_reviewable():
    assert not is_reviewable_diff("")


# --- candidate selection: one advisory can list several fix commits ---


def candidate(id, repo="acme/app", commit="a1", cve_id=None):
    return {"id": id, "repo": repo, "commit": commit, "cve_id": cve_id, "category": "x"}


def test_one_advisory_yields_one_example():
    # Regression: three fix commits for PYSEC-2012-7 filled the whole positive class and,
    # because the diff file is named after the advisory, overwrote each other on disk.
    picked = select_candidates(
        [
            candidate("PYSEC-2012-7", commit="a1"),
            candidate("PYSEC-2012-7", commit="a2"),
            candidate("PYSEC-2012-7", commit="a3"),
        ]
    )
    assert len(picked) == 1


def test_newer_advisories_come_first():
    picked = select_candidates([candidate("PYSEC-2012-7"), candidate("PYSEC-2024-1")])
    assert [c["id"] for c in picked] == ["PYSEC-2024-1", "PYSEC-2012-7"]


def test_repos_are_interleaved_so_one_project_does_not_dominate():
    picked = select_candidates(
        [
            candidate("PYSEC-2024-1", repo="django/django"),
            candidate("PYSEC-2024-2", repo="django/django"),
            candidate("PYSEC-2024-3", repo="pallets/flask"),
        ]
    )
    assert [c["repo"] for c in picked[:2]] == ["django/django", "pallets/flask"]


# --- manifest validation: the labels are the whole experiment, so guard them ---


def test_rejects_entry_without_a_label():
    with pytest.raises(ValueError, match="is_vulnerable"):
        validate_manifest([entry(is_vulnerable=None)])


def test_rejects_unbalanced_dataset():
    entries = [entry(id=f"v{i}") for i in range(5)] + [entry(id="b0", is_vulnerable=False)]
    with pytest.raises(ValueError, match="balance"):
        validate_manifest(entries)


def test_rejects_truncated_dataset():
    # A rate-limited build once produced 2 balanced examples and passed validation.
    entries = [entry(), entry(id="b0", is_vulnerable=False)]
    with pytest.raises(ValueError, match="at least"):
        validate_manifest(entries, minimum=20)


def test_accepts_balanced_dataset():
    entries = [entry(id=f"v{i}") for i in range(3)] + [
        entry(id=f"b{i}", is_vulnerable=False, cve_id=None, category=None) for i in range(3)
    ]
    validate_manifest(entries)


def test_write_manifest_round_trips(tmp_path):
    entries = [entry(), entry(id="b0", is_vulnerable=False, cve_id=None, category=None)]
    path = tmp_path / "manifest.json"
    write_manifest(entries, path)

    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert [e["is_vulnerable"] for e in loaded] == [True, False]
