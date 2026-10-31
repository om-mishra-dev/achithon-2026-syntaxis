"""CMD-004: Vulnerable - subprocess.run with shell=True and tainted input."""
import subprocess
from flask import request


def run_grep():
    pattern = request.args.get('pattern')
    subprocess.run(f"grep {pattern} /var/log/app.log", shell=True)

