"""Dependency data models and record definitions."""

from __future__ import annotations

import re
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class DependencyScope(str, Enum):
    PRODUCTION = "PRODUCTION"
    DEVELOPMENT = "DEVELOPMENT"
    OPTIONAL = "OPTIONAL"
    PEER = "PEER"
    UNKNOWN = "UNKNOWN"


class ResolutionStatus(str, Enum):
    RESOLVED = "RESOLVED"
    UNRESOLVED_CONSTRAINT = "UNRESOLVED_CONSTRAINT"
    UNRESOLVED_TRANSITIVE = "UNRESOLVED_TRANSITIVE"


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalization: lowercase and runs of [-_.] replaced by single -"""
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def normalize_npm_name(name: str) -> str:
    """npm package name normalization: lowercase, preserve scope if present"""
    return name.lower().strip()


def normalize_package_name(ecosystem: str, name: str) -> str:
    if ecosystem.lower() in ("pypi", "python"):
        return normalize_pypi_name(name)
    if ecosystem.lower() in ("npm", "javascript", "typescript"):
        return normalize_npm_name(name)
    return name.lower().strip()


class DependencyRecord(BaseModel):
    name: str
    normalized_name: str
    ecosystem: str
    version: Optional[str] = None
    constraint: Optional[str] = None
    is_direct: bool = True
    scope: DependencyScope = DependencyScope.PRODUCTION
    source_manifest: str
    declaration_line: Optional[int] = None
    dependencies: Dict[str, str] = Field(default_factory=dict)
    resolution_status: ResolutionStatus = ResolutionStatus.UNRESOLVED_CONSTRAINT
    parent_package: Optional[str] = None

