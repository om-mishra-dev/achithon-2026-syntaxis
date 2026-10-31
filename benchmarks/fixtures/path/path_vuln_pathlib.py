"""PATH-003: Vulnerable - pathlib.Path with request.args user input."""
from pathlib import Path
from flask import request


def get_file():
    user_path = request.args.get('path')
    return Path(user_path).read_text()

