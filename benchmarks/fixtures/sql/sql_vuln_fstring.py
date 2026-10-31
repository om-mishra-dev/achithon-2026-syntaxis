"""SQL-001: Vulnerable - F-string SQL injection via request.args taint source."""
from flask import request
import sqlite3


def get_user(db):
    uid = request.args.get('id')
    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return cursor.fetchall()

