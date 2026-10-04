import sqlite3


def find_user(conn: sqlite3.Connection, username: str):
    query = "SELECT id, username, email FROM users WHERE username = ?"
    return conn.execute(query, (username,)).fetchone()
