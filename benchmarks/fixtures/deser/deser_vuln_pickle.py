"""DESER-001: Vulnerable - pickle.loads with request.data taint source."""
import pickle
from flask import request


def deserialize():
    data = request.data
    obj = pickle.loads(data)
    return obj

