import sqlite3


def get_connection():
    return sqlite3.connect("app.db")


def get_user(conn, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchone()
