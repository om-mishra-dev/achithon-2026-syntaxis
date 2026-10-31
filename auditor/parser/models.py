"""Data models for AST parsing, code entities, and structural relationships."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from auditor.core.models import CodeLocation


class SourceLocation(BaseModel):
    file_path: str
    start_line: int
    start_col: int = 1
    end_line: int
    end_col: int = 1
    snippet: Optional[str] = None

    def to_code_location(self) -> CodeLocation:
        return CodeLocation(
            file_path=self.file_path,
            line=self.start_line,
            col=self.start_col,
            end_line=self.end_line,
            end_col=self.end_col,
            snippet=self.snippet,
        )


class FunctionDefinition(BaseModel):
    name: str
    qualified_name: str
    location: SourceLocation
    parameters: List[str] = Field(default_factory=list)
    is_async: bool = False
    decorators: List[str] = Field(default_factory=list)


class ClassDefinition(BaseModel):
    name: str
    location: SourceLocation
    bases: List[str] = Field(default_factory=list)
    methods: List[str] = Field(default_factory=list)


class ImportStatement(BaseModel):
    module: str
    imported_names: List[str] = Field(default_factory=list)
    alias: Optional[str] = None
    location: SourceLocation
    is_from_import: bool = False


class CallExpression(BaseModel):
    callee_name: str
    location: SourceLocation
    arguments: List[str] = Field(default_factory=list)
    keywords: Dict[str, str] = Field(default_factory=dict)
    enclosing_function: Optional[str] = None


class VariableAssignment(BaseModel):
    target: str
    value_expr: str
    location: SourceLocation
    enclosing_function: Optional[str] = None


class ParsedFile(BaseModel):
    file_path: str
    relative_path: str
    language: str
    is_success: bool = True
    parse_error: Optional[str] = None
    functions: List[FunctionDefinition] = Field(default_factory=list)
    classes: List[ClassDefinition] = Field(default_factory=list)
    imports: List[ImportStatement] = Field(default_factory=list)
    calls: List[CallExpression] = Field(default_factory=list)
    assignments: List[VariableAssignment] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

