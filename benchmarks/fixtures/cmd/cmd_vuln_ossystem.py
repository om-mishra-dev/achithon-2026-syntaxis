"""CMD-001: Vulnerable - os.system with request.args taint source."""
import os
from flask import request


def run_command():
    cmd = request.args.get('cmd')
    os.system(cmd)

