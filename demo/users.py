import sqlite3


def find_user(conn: sqlite3.Connection, username: str):
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchone()
