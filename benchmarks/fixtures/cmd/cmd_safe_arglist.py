"""CMD-002: Safe - subprocess.run with static arg list, shell=False."""
import subprocess


def list_files():
    result = subprocess.run(['ls', '-la'], shell=False, capture_output=True)
    return result.stdout

