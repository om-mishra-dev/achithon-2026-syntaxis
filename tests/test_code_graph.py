"""Unit tests for NetworkX code relationship graph and call resolution."""

import unittest
from auditor.graph.code_graph import CodeGraphService
from auditor.parser.models import (
    CallExpression,
    ClassDefinition,
    FunctionDefinition,
    ImportStatement,
    ParsedFile,
    SourceLocation,
)


class TestCodeGraph(unittest.TestCase):

    def test_code_graph_cross_file_resolution(self):
        # File A defines 'execute_query'
        loc_a = SourceLocation(file_path="db.py", start_line=1, start_col=1, end_line=5, end_col=1)
        func_db = FunctionDefinition(name="execute_query", qualified_name="execute_query", location=loc_a)
        file_a = ParsedFile(
            file_path="/repo/db.py",
            relative_path="db.py",
            language="python",
            functions=[func_db],
        )

        # File B imports 'execute_query' from 'db' and calls it
        loc_b_imp = SourceLocation(file_path="app.py", start_line=1, start_col=1, end_line=1, end_col=30)
        imp = ImportStatement(module="db", imported_names=["execute_query"], location=loc_b_imp)

        loc_b_fn = SourceLocation(file_path="app.py", start_line=3, start_col=1, end_line=8, end_col=1)
        func_app = FunctionDefinition(name="handle_api", qualified_name="handle_api", location=loc_b_fn)

        loc_b_call = SourceLocation(file_path="app.py", start_line=5, start_col=5, end_line=5, end_col=25)
        call = CallExpression(
            callee_name="execute_query",
            location=loc_b_call,
            enclosing_function="handle_api",
        )

        file_b = ParsedFile(
            file_path="/repo/app.py",
            relative_path="app.py",
            language="python",
            imports=[imp],
            functions=[func_app],
            calls=[call],
        )

        service = CodeGraphService()
        graph = service.build_graph([file_a, file_b])

        # Verify nodes exist
        self.assertTrue(graph.has_node("file:app.py"))
        self.assertTrue(graph.has_node("file:db.py"))
        self.assertTrue(graph.has_node("func:db.py::execute_query"))
        self.assertTrue(graph.has_node("func:app.py::handle_api"))

        # Verify cross-file resolution: call node in app.py resolves to func in db.py
        call_node_id = "call:app.py::execute_query@5_0"
        self.assertTrue(graph.has_node(call_node_id))
        self.assertTrue(graph.has_edge(call_node_id, "func:db.py::execute_query"))

        # Verify metrics
        serialized = service.to_dict()
        metrics = serialized["metrics"]
        self.assertEqual(metrics["files_count"], 2)
        self.assertEqual(metrics["functions_count"], 2)
        self.assertEqual(metrics["resolved_calls"], 1)
        self.assertEqual(metrics["unresolved_calls"], 0)


if __name__ == "__main__":
    unittest.main()

