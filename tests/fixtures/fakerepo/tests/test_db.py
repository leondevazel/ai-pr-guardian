from app.db import get_user


def test_get_user_returns_row():
    assert get_user(FakeConn(), 1) is not None
