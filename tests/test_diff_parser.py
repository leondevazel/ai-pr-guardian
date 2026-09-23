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


def test_empty_diff_yields_no_files():
    assert parse_diff("").files == []
