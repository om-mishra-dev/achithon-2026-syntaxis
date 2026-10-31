"""Unit tests for multi-language AST parsing (Python and JavaScript/TypeScript)."""

import tempfile
import unittest
from pathlib import Path

from auditor.core.models import DiscoveredFile
from auditor.parser.ast_engine import ASTEngine
from auditor.parser.js_parser import parse_js_ts_source
from auditor.parser.python_parser import parse_python_source


class TestASTParser(unittest.TestCase):

    def test_python_parsing_valid(self):
        code = """
import os
from subprocess import Popen, PIPE

class VulnerableService:
    def __init__(self, name: str):
        self.name = name

    def execute_task(self, command: str):
        cleaned = command.strip()
        os.system(cleaned)
"""
        parsed = parse_python_source(code, "test.py", "src/test.py")
        self.assertTrue(parsed.is_success)
        self.assertIsNone(parsed.parse_error)

        # Classes
        self.assertEqual(len(parsed.classes), 1)
        self.assertEqual(parsed.classes[0].name, "VulnerableService")

        # Functions
        func_names = [f.name for f in parsed.functions]
        self.assertIn("__init__", func_names)
        self.assertIn("execute_task", func_names)

        # Qualified names
        exec_func = next(f for f in parsed.functions if f.name == "execute_task")
        self.assertEqual(exec_func.qualified_name, "VulnerableService.execute_task")
        self.assertEqual(exec_func.parameters, ["self", "command"])

        # Imports
        modules = [imp.module for imp in parsed.imports]
        self.assertIn("os", modules)
        self.assertIn("subprocess", modules)

        # Calls
        callees = [c.callee_name for c in parsed.calls]
        self.assertIn("os.system", callees)

        # Assignments
        targets = [a.target for a in parsed.assignments]
        self.assertIn("cleaned", targets)

    def test_python_parsing_syntax_error(self):
        bad_code = "def invalid_syntax(x\n    return x +"
        parsed = parse_python_source(bad_code, "bad.py", "bad.py")
        self.assertFalse(parsed.is_success)
        self.assertIn("SyntaxError", parsed.parse_error)

    def test_js_ts_parsing_valid(self):
        js_code = """
import { exec } from 'child_process';
const express = require('express');

class AppHandler extends BaseController {
    handleRequest(req, res) {
        const cmd = req.query.cmd;
        exec(cmd);
    }
}
"""
        parsed = parse_js_ts_source(js_code, "server.js", "src/server.js", "javascript")
        self.assertTrue(parsed.is_success)

        # Imports
        mods = [imp.module for imp in parsed.imports]
        self.assertIn("child_process", mods)
        self.assertIn("express", mods)

        # Classes
        self.assertEqual(len(parsed.classes), 1)
        self.assertEqual(parsed.classes[0].name, "AppHandler")
        self.assertEqual(parsed.classes[0].bases, ["BaseController"])

        # Calls
        callees = [c.callee_name for c in parsed.calls]
        self.assertIn("exec", callees)

        # Assignments
        targets = [a.target for a in parsed.assignments]
        self.assertIn("cmd", targets)

    def test_ast_engine_dispatcher_and_safety_checks(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir) / "empty.py"
            p.write_text("# empty file", encoding="utf-8")

            disc_file = DiscoveredFile(
                path=str(p),
                relative_path="empty.py",
                language="python",
                size_bytes=p.stat().st_size,
            )

            engine = ASTEngine()
            result = engine.parse_file(disc_file)
            self.assertIsNotNone(result)
            self.assertTrue(result.is_success)
            self.assertEqual(len(result.functions), 0)


if __name__ == "__main__":
    unittest.main()

