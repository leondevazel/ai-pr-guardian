from pathlib import Path

from guardian.diff_parser import parse_diff

SAMPLE = (Path(__file__).parent / "fixtures" / "sample.diff").read_text()


def test_parses_changed_file_paths():
    ctx = parse_diff(SAMPLE)
    assert [f.path for f in ctx.files] == ["app/db.py"]


def test_captures_added_lines_with_absolute_line_numbers():
    ctx = parse_diff(SAMPLE)
    added = ctx.files[0].hunks[0].added_lines
    assert (12, '    query = f"SELECT * FROM users WHERE id = {user_id}"') in added


def test_context_includes_unchanged_surrounding_lines():
    ctx = parse_diff(SAMPLE)
    assert "def get_connection():" in ctx.files[0].hunks[0].context


def test_context_keeps_diff_markers_so_deleted_code_is_distinguishable():
    # Regression: markers were dropped, so removed and added lines ran together into code that
    # never existed, and agents blocked benign refactors for "unreachable" branches.
    context = parse_diff(SAMPLE).files[0].hunks[0].context
    assert '+    query = f"SELECT * FROM users WHERE id = {user_id}"' in context
    assert " def get_connection():" in context


def test_removed_lines_are_captured_separately():
    fix = (
        "diff --git a/app/db.py b/app/db.py\n"
        "--- a/app/db.py\n"
        "+++ b/app/db.py\n"
        "@@ -1,2 +1,1 @@\n"
        "-old_call()\n"
        "-second_old()\n"
        "+new_call()\n"
    )
    removed = parse_diff(fix).files[0].hunks[0].removed_lines
    assert [text for _, text in removed] == ["old_call()", "second_old()"]


def test_empty_diff_yields_no_files():
    assert parse_diff("").files == []
