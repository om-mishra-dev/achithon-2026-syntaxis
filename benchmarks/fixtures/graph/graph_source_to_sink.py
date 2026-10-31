"""GRAPH-001: Vulnerable - taint flows from request.args through helper to os.system."""
import os
from flask import request


def get_input():
    return request.args.get('data')


def process(value):
    os.system(value)


def handle():
    val = get_input()
    process(val)

