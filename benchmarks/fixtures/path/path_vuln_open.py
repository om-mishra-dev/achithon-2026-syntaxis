"""PATH-001: Vulnerable - open() with user-controlled path from request.args."""
from flask import request


def read_file():
    path = request.args.get('f')
    with open(path) as fh:
        return fh.read()

