"""REMEDIATION-002: CMD injection via os.system - expects REQUIRES_REVIEW remediation."""
import os
from flask import request


def run_tool():
    tool = request.args.get('tool')
    os.system(tool)

