"""SQL-002: Safe - Parameterized query prevents SQL injection."""
from flask import request
import sqlite3


def get_user(db):
    uid = request.args.get('id')
    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    return cursor.fetchall()

