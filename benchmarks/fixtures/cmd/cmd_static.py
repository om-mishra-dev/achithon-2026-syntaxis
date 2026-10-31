"""CMD-003: Safe - Static os.system call with no user input."""
import os


def list_files():
    os.system('ls -la')

