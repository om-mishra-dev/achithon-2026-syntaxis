"""Unit tests for local variable taint tracking and source-to-sink propagation."""

import unittest
from auditor.core.models import Confidence
from auditor.parser.python_parser import parse_python_source
from auditor.sast.engine import SASTEngine


class TestDataFlow(unittest.TestCase):

    def setUp(self):
        self.engine = SASTEngine()

    def test_multi_step_assignment_propagation(self):
        code = """
import os

def process_input():
    raw_val = request.args.get('target')
    step1 = raw_val
    step2 = f"ping -c 1 {step1}"
    final_cmd = step2
    os.system(final_cmd)
"""
        parsed = parse_python_source(code, "flow.py", "flow.py")
        findings = self.engine.scan_file(parsed)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.cwe_id, "CWE-78")
        self.assertEqual(finding.confidence, Confidence.CONFIRMED)

        # Verify evidence includes both sink and source
        source_types = [ev.source_type for ev in finding.evidence]
        self.assertIn("SAST_SOURCE", source_types)
        self.assertIn("SAST_SINK", source_types)

        # Verify source line points to request.args line (line 5)
        src_ev = next(ev for ev in finding.evidence if ev.source_type == "SAST_SOURCE")
        self.assertEqual(src_ev.location.line, 5)

        # Verify sink line points to os.system line (line 9)
        sink_ev = next(ev for ev in finding.evidence if ev.source_type == "SAST_SINK")
        self.assertEqual(sink_ev.location.line, 9)

    def test_sanitizer_clears_taint(self):
        code = """
import os
import shlex

def process_sanitized():
    raw_val = request.args.get('target')
    safe_val = shlex.quote(raw_val)
    os.system(f"ping {safe_val}")
"""
        parsed = parse_python_source(code, "safe_flow.py", "safe_flow.py")
        findings = self.engine.scan_file(parsed)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()

