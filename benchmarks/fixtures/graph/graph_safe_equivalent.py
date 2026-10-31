"""GRAPH-002: Safe - input validated before use; no direct sink exposure."""
import subprocess
from flask import request


def get_input():
    return request.args.get('data')


def process(value):
    # Safe: using fixed arg list with no shell interpretation
    subprocess.run(['echo', value], shell=False)


def handle():
    val = get_input()
    process(val)

