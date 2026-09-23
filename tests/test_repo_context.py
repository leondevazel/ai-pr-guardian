from pathlib import Path

from guardian.tools.repo_context import get_context

REPO = str(Path(__file__).parent / "fixtures" / "fakerepo")


def test_finds_enclosing_function_for_a_line_inside_it():
    ctx = get_context(REPO, "app/db.py", line=9)
    assert "def get_user(conn, user_id):" in ctx.enclosing_function
    assert "def get_connection" not in ctx.enclosing_function


def test_lists_tests_referencing_the_enclosing_function():
    ctx = get_context(REPO, "app/db.py", line=9)
    assert any(path.endswith("tests/test_db.py") for path in ctx.related_tests)


def test_extracts_imports_of_the_changed_file():
    ctx = get_context(REPO, "app/db.py", line=9)
    assert "sqlite3" in ctx.imports


def test_line_outside_any_function_falls_back_to_surrounding_lines():
    ctx = get_context(REPO, "app/db.py", line=1)
    assert "import sqlite3" in ctx.enclosing_function


def test_non_python_file_returns_raw_window_without_crashing():
    ctx = get_context(REPO, "app/config.yaml", line=2)
    assert "debug: true" in ctx.enclosing_function
    assert ctx.imports == []


def test_missing_file_returns_empty_context():
    ctx = get_context(REPO, "app/does_not_exist.py", line=3)
    assert ctx.enclosing_function == ""
    assert ctx.imports == []
    assert ctx.related_tests == []
