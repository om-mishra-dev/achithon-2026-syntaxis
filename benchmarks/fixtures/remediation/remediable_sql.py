"""REMEDIATION-001: Remediable SQL - f-string SQL injection, expects parameterization patch."""
from flask import request
import sqlite3


def search_user(db):
    name = request.args.get('name')
    cur = db.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchall()

