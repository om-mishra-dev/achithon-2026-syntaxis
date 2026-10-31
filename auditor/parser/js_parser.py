"""JavaScript and TypeScript structural parser extracting code entities and calls."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from .models import (
    CallExpression,
    ClassDefinition,
    FunctionDefinition,
    ImportStatement,
    ParsedFile,
    SourceLocation,
    VariableAssignment,
)

# Regex patterns for JavaScript/TypeScript structural extraction
IMPORT_ESM_REGEX = re.compile(
    r"""import\s+(?:(?:(?:\{[^}]+\})|(?:[A-Za-z0-9_$]+))\s+from\s+)?['"]([^'"]+)['"]""",
    re.MULTILINE,
)
REQUIRE_REGEX = re.compile(
    r"""(?:const|let|var)\s+(?:\{?([A-Za-z0-9_$,\s]+)\}?)\s*=\s*require\(['"]([^'"]+)['"]\)""",
    re.MULTILINE,
)
FUNC_DEF_REGEX = re.compile(
    r"""(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_$]+)\s*\(([^)]*)\)""",
    re.MULTILINE,
)
ARROW_FUNC_REGEX = re.compile(
    r"""(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>""",
    re.MULTILINE,
)
CLASS_DEF_REGEX = re.compile(
    r"""(?:export\s+)?class\s+([A-Za-z0-9_$]+)(?:\s+extends\s+([A-Za-z0-9_$.]+))?""",
    re.MULTILINE,
)
CALL_EXPR_REGEX = re.compile(
    r"""\b([A-Za-z0-9_$.]+)\s*\(([^)]*)\)""",
    re.MULTILINE,
)
ASSIGN_REGEX = re.compile(
    r"""(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*([^;\n]+)""",
    re.MULTILINE,
)


def parse_js_ts_source(code: str, file_path: str, relative_path: str, language: str) -> ParsedFile:
    """Parse JavaScript/TypeScript code using resilient regex-based structural analysis."""
    lines = code.splitlines()
    functions: List[FunctionDefinition] = []
    classes: List[ClassDefinition] = []
    imports: List[ImportStatement] = []
    calls: List[CallExpression] = []
    assignments: List[VariableAssignment] = []

    def get_line_col(pos: int) -> tuple[int, int]:
        line = code.count("\n", 0, pos) + 1
        last_nl = code.rfind("\n", 0, pos)
        col = pos - last_nl if last_nl != -1 else pos + 1
        return line, col

    def get_snippet(line: int) -> str:
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()
        return ""

    # 1. Imports
    for m in IMPORT_ESM_REGEX.finditer(code):
        mod = m.group(1)
        start_line, start_col = get_line_col(m.start())
        loc = SourceLocation(
            file_path=relative_path,
            start_line=start_line,
            start_col=start_col,
            end_line=start_line,
            end_col=start_col + len(m.group(0)),
            snippet=get_snippet(start_line),
        )
        imports.append(ImportStatement(module=mod, location=loc, is_from_import=True))

    for m in REQUIRE_REGEX.finditer(code):
        names_raw = m.group(1)
        mod = m.group(2)
        start_line, start_col = get_line_col(m.start())
        loc = SourceLocation(
            file_path=relative_path,
            start_line=start_line,
            start_col=start_col,
            end_line=start_line,
            end_col=start_col + len(m.group(0)),
            snippet=get_snippet(start_line),
        )
        names = [n.strip() for n in names_raw.split(",") if n.strip()]
        imports.append(ImportStatement(module=mod, imported_names=names, location=loc, is_from_import=False))

    # 2. Classes
    for m in CLASS_DEF_REGEX.finditer(code):
        cname = m.group(1)
        base = m.group(2)
        start_line, start_col = get_line_col(m.start())
        loc = SourceLocation(
            file_path=relative_path,
            start_line=start_line,
            start_col=start_col,
            end_line=start_line,
            end_col=start_col + len(m.group(0)),
            snippet=get_snippet(start_line),
        )
        classes.append(ClassDefinition(name=cname, location=loc, bases=[base] if base else []))

    # 3. Functions
    for m in FUNC_DEF_REGEX.finditer(code):
        fname = m.group(1)
        params = [p.strip() for p in m.group(2).split(",") if p.strip()]
        start_line, start_col = get_line_col(m.start())
        loc = SourceLocation(
            file_path=relative_path,
            start_line=start_line,
            start_col=start_col,
            end_line=start_line,
            end_col=start_col + len(m.group(0)),
            snippet=get_snippet(start_line),
        )
        functions.append(FunctionDefinition(name=fname, qualified_name=fname, location=loc, parameters=params))

    for m in ARROW_FUNC_REGEX.finditer(code):
        fname = m.group(1)
        params = [p.strip() for p in m.group(2).split(",") if p.strip()]
        start_line, start_col = get_line_col(m.start())
        loc = SourceLocation(
            file_path=relative_path,
            start_line=start_line,
            start_col=start_col,
            end_line=start_line,
            end_col=start_col + len(m.group(0)),
            snippet=get_snippet(start_line),
        )
        functions.append(FunctionDefinition(name=fname, qualified_name=fname, location=loc, parameters=params))

    # 4. Assignments
    for m in ASSIGN_REGEX.finditer(code):
        var_name = m.group(1)
        expr_val = m.group(2).strip()
        start_line, start_col = get_line_col(m.start())
        loc = SourceLocation(
            file_path=relative_path,
            start_line=start_line,
            start_col=start_col,
            end_line=start_line,
            end_col=start_col + len(m.group(0)),
            snippet=get_snippet(start_line),
        )
        assignments.append(VariableAssignment(target=var_name, value_expr=expr_val, location=loc))

    # 5. Calls
    for m in CALL_EXPR_REGEX.finditer(code):
        callee = m.group(1)
        # Skip control flow keywords (if, while, for, switch, catch)
        if callee in ("if", "while", "for", "switch", "catch", "function"):
            continue
        args = [a.strip() for a in m.group(2).split(",") if a.strip()]
        start_line, start_col = get_line_col(m.start())
        loc = SourceLocation(
            file_path=relative_path,
            start_line=start_line,
            start_col=start_col,
            end_line=start_line,
            end_col=start_col + len(m.group(0)),
            snippet=get_snippet(start_line),
        )
        calls.append(CallExpression(callee_name=callee, location=loc, arguments=args))

    return ParsedFile(
        file_path=file_path,
        relative_path=relative_path,
        language=language,
        is_success=True,
        functions=functions,
        classes=classes,
        imports=imports,
        calls=calls,
        assignments=assignments,
    )

