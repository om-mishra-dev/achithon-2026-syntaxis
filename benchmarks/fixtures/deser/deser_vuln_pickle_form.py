"""DESER-003: Vulnerable - pickle.loads with request.form input."""
import pickle
from flask import request


def load_object():
    raw = request.form.get('data')
    if raw:
        return pickle.loads(raw.encode())
    return None

