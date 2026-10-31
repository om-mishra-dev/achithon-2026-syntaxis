"""Python AST parser using standard-library ast with full node extraction."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import List, Optional

from .models import (
    CallExpression,
    ClassDefinition,
    FunctionDefinition,
    ImportStatement,
    ParsedFile,
    SourceLocation,
    VariableAssignment,
)


def _get_call_name(node: ast.AST) -> str:
    """Resolve AST call target to a dotted string (e.g. os.system, cursor.execute)."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        parent = _get_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    elif isinstance(node, ast.Call):
        return _get_call_name(node.func)
    return "<dynamic_call>"


class PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, lines: List[str]):
        self.file_path = file_path
        self.lines = lines
        self.functions: List[FunctionDefinition] = []
        self.classes: List[ClassDefinition] = []
        self.imports: List[ImportStatement] = []
        self.calls: List[CallExpression] = []
        self.assignments: List[VariableAssignment] = []

        self._class_stack: List[str] = []
        self._func_stack: List[str] = []

    def _get_snippet(self, start_line: int, end_line: int) -> str:
        if 1 <= start_line <= len(self.lines):
            return "\n".join(self.lines[start_line - 1 : min(end_line, len(self.lines))]).strip()
        return ""

    def visit_ClassDef(self, node: ast.ClassDef):
        loc = SourceLocation(
            file_path=self.file_path,
            start_line=node.lineno,
            start_col=node.col_offset + 1,
            end_line=getattr(node, "end_lineno", node.lineno),
            end_col=getattr(node, "end_col_offset", 1) + 1,
            snippet=self._get_snippet(node.lineno, getattr(node, "end_lineno", node.lineno)),
        )

        bases = []
        for b in node.bases:
            if isinstance(b, ast.Name):
                bases.append(b.id)
            elif isinstance(b, ast.Attribute):
                bases.append(_get_call_name(b))

        self.classes.append(ClassDefinition(name=node.name, location=loc, bases=bases))

        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._record_func(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._record_func(node, is_async=True)

    def _record_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool):
        loc = SourceLocation(
            file_path=self.file_path,
            start_line=node.lineno,
            start_col=node.col_offset + 1,
            end_line=getattr(node, "end_lineno", node.lineno),
            end_col=getattr(node, "end_col_offset", 1) + 1,
            snippet=self._get_snippet(node.lineno, getattr(node, "end_lineno", node.lineno)),
        )

        params = [arg.arg for arg in node.args.args]
        decorators = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decorators.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                decorators.append(_get_call_name(dec))

        prefix = ".".join(self._class_stack)
        qname = f"{prefix}.{node.name}" if prefix else node.name

        self.functions.append(
            FunctionDefinition(
                name=node.name,
                qualified_name=qname,
                location=loc,
                parameters=params,
                is_async=is_async,
                decorators=decorators,
            )
        )

        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    def visit_Import(self, node: ast.Import):
        loc = SourceLocation(
            file_path=self.file_path,
            start_line=node.lineno,
            start_col=node.col_offset + 1,
            end_line=getattr(node, "end_lineno", node.lineno),
            end_col=getattr(node, "end_col_offset", 1) + 1,
            snippet=self._get_snippet(node.lineno, getattr(node, "end_lineno", node.lineno)),
        )
        for alias in node.names:
            self.imports.append(
                ImportStatement(
                    module=alias.name,
                    imported_names=[alias.name],
                    alias=alias.asname,
                    location=loc,
                    is_from_import=False,
                )
            )

    def visit_ImportFrom(self, node: ast.ImportFrom):
        loc = SourceLocation(
            file_path=self.file_path,
            start_line=node.lineno,
            start_col=node.col_offset + 1,
            end_line=getattr(node, "end_lineno", node.lineno),
            end_col=getattr(node, "end_col_offset", 1) + 1,
            snippet=self._get_snippet(node.lineno, getattr(node, "end_lineno", node.lineno)),
        )
        names = [alias.name for alias in node.names]
        self.imports.append(
            ImportStatement(
                module=node.module or "",
                imported_names=names,
                location=loc,
                is_from_import=True,
            )
        )

    def visit_Call(self, node: ast.Call):
        callee = _get_call_name(node.func)
        loc = SourceLocation(
            file_path=self.file_path,
            start_line=node.lineno,
            start_col=node.col_offset + 1,
            end_line=getattr(node, "end_lineno", node.lineno),
            end_col=getattr(node, "end_col_offset", 1) + 1,
            snippet=self._get_snippet(node.lineno, getattr(node, "end_lineno", node.lineno)),
        )

        args_str = []
        for arg in node.args:
            try:
                args_str.append(ast.unparse(arg))
            except Exception:
                args_str.append("<expr>")

        keywords_dict = {}
        for kw in node.keywords:
            if kw.arg:
                try:
                    keywords_dict[kw.arg] = ast.unparse(kw.value)
                except Exception:
                    keywords_dict[kw.arg] = "<expr>"

        enclosing = self._func_stack[-1] if self._func_stack else None

        self.calls.append(
            CallExpression(
                callee_name=callee,
                location=loc,
                arguments=args_str,
                keywords=keywords_dict,
                enclosing_function=enclosing,
            )
        )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                loc = SourceLocation(
                    file_path=self.file_path,
                    start_line=node.lineno,
                    start_col=node.col_offset + 1,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    end_col=getattr(node, "end_col_offset", 1) + 1,
                    snippet=self._get_snippet(node.lineno, getattr(node, "end_lineno", node.lineno)),
                )
                try:
                    val_str = ast.unparse(node.value)
                except Exception:
                    val_str = "<expr>"
                enclosing = self._func_stack[-1] if self._func_stack else None
                self.assignments.append(
                    VariableAssignment(
                        target=target.id,
                        value_expr=val_str,
                        location=loc,
                        enclosing_function=enclosing,
                    )
                )
        self.generic_visit(node)


def parse_python_source(code: str, file_path: str, relative_path: str) -> ParsedFile:
    """Parse Python source code into a structured ParsedFile model."""
    lines = code.splitlines()
    try:
        tree = ast.parse(code, filename=file_path)
    except SyntaxError as err:
        loc = SourceLocation(
            file_path=relative_path,
            start_line=err.lineno or 1,
            start_col=err.offset or 1,
            end_line=err.lineno or 1,
            end_col=(err.offset or 1) + 1,
            snippet=lines[err.lineno - 1] if err.lineno and 1 <= err.lineno <= len(lines) else "",
        )
        return ParsedFile(
            file_path=file_path,
            relative_path=relative_path,
            language="python",
            is_success=False,
            parse_error=f"SyntaxError at line {err.lineno}: {err.msg}",
        )

    visitor = PythonASTVisitor(relative_path, lines)
    visitor.visit(tree)

    return ParsedFile(
        file_path=file_path,
        relative_path=relative_path,
        language="python",
        is_success=True,
        functions=visitor.functions,
        classes=visitor.classes,
        imports=visitor.imports,
        calls=visitor.calls,
        assignments=visitor.assignments,
    )

