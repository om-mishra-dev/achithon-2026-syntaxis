"""SQL-003: Safe - Static SQL query with no user input."""
import sqlite3


def get_all_users(db):
    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()

