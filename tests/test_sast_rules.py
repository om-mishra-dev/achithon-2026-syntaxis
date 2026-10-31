"""Unit tests for deterministic SAST rules (CWE-78, CWE-89, CWE-22, CWE-502, CWE-79)."""

import unittest
from auditor.core.models import FindingType, Severity
from auditor.parser.python_parser import parse_python_source
from auditor.sast.engine import SASTEngine


class TestSASTRules(unittest.TestCase):

    def setUp(self):
        self.engine = SASTEngine()

    def test_cwe_78_command_injection_vulnerable_and_safe(self):
        code_vuln = """
import os

def handle_request():
    user_cmd = request.args.get('command')
    os.system(f"echo {user_cmd}")
"""
        parsed_vuln = parse_python_source(code_vuln, "vuln.py", "vuln.py")
        findings = self.engine.scan_file(parsed_vuln)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-78")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

        # Safe equivalent: argument list with shell=False or static string
        code_safe = """
import subprocess
import os

def handle_safe():
    subprocess.run(["echo", "hello"])
    os.system("echo safe_literal")
"""
        parsed_safe = parse_python_source(code_safe, "safe.py", "safe.py")
        safe_findings = self.engine.scan_file(parsed_safe)
        self.assertEqual(len(safe_findings), 0)

    def test_cwe_89_sql_injection_vulnerable_and_safe(self):
        code_vuln = """
def get_user(cursor):
    uid = request.args['id']
    cursor.execute(f"SELECT * FROM users WHERE id = '{uid}'")
"""
        parsed_vuln = parse_python_source(code_vuln, "db_vuln.py", "db_vuln.py")
        findings = self.engine.scan_file(parsed_vuln)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-89")
        self.assertEqual(findings[0].severity, Severity.HIGH)

        # Safe equivalent: parameterized query
        code_safe = """
def get_user_safe(cursor):
    uid = request.args['id']
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
"""
        parsed_safe = parse_python_source(code_safe, "db_safe.py", "db_safe.py")
        safe_findings = self.engine.scan_file(parsed_safe)
        self.assertEqual(len(safe_findings), 0)

    def test_cwe_22_path_traversal_vulnerable_and_safe(self):
        code_vuln = """
def read_user_file():
    target = request.args.get('filename')
    with open(target, 'r') as f:
        return f.read()
"""
        parsed_vuln = parse_python_source(code_vuln, "fs_vuln.py", "fs_vuln.py")
        findings = self.engine.scan_file(parsed_vuln)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-22")

        # Safe: sanitized with os.path.basename or static file
        code_safe = """
import os

def read_safe_file():
    target = request.args.get('filename')
    safe_name = os.path.basename(target)
    with open("config.json", 'r') as f:
        pass
    with open(safe_name, 'r') as f:
        pass
"""
        parsed_safe = parse_python_source(code_safe, "fs_safe.py", "fs_safe.py")
        safe_findings = self.engine.scan_file(parsed_safe)
        self.assertEqual(len(safe_findings), 0)

    def test_cwe_502_insecure_deserialization_vulnerable_and_safe(self):
        code_vuln = """
import pickle

def load_session(raw_data):
    return pickle.loads(raw_data)
"""
        parsed_vuln = parse_python_source(code_vuln, "ser_vuln.py", "ser_vuln.py")
        findings = self.engine.scan_file(parsed_vuln)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-502")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

        # Safe equivalent: json.loads
        code_safe = """
import json

def load_safe_session(raw_data):
    return json.loads(raw_data)
"""
        parsed_safe = parse_python_source(code_safe, "ser_safe.py", "ser_safe.py")
        safe_findings = self.engine.scan_file(parsed_safe)
        self.assertEqual(len(safe_findings), 0)

    def test_cwe_79_xss_vulnerable_and_safe(self):
        code_vuln = """
from flask import render_template_string

def show_page():
    name = request.args.get('name')
    return render_template_string(f"<h1>Hello {name}</h1>")
"""
        parsed_vuln = parse_python_source(code_vuln, "xss_vuln.py", "xss_vuln.py")
        findings = self.engine.scan_file(parsed_vuln)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-79")

        # Safe equivalent: render_template with template file
        code_safe = """
from flask import render_template

def show_safe_page():
    name = request.args.get('name')
    return render_template("profile.html", name=name)
"""
        parsed_safe = parse_python_source(code_safe, "xss_safe.py", "xss_safe.py")
        safe_findings = self.engine.scan_file(parsed_safe)
        self.assertEqual(len(safe_findings), 0)


if __name__ == "__main__":
    unittest.main()

