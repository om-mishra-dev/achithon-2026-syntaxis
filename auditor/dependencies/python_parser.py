"""Parsers for Python dependency manifests: requirements.txt, pyproject.toml, Pipfile.lock, poetry.lock."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import List, Optional

from .models import (
    DependencyRecord,
    DependencyScope,
    ResolutionStatus,
    normalize_pypi_name,
)

# Regex matching package name and version specification
# Handles PEP 508 names: letters, numbers, _, -, .
REQ_REGEX = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9]|[A-Za-z0-9])"
    r"(?:\[[A-Za-z0-9._,-]+\])?"  # optional extras [security,tests]
    r"\s*(==|===|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9.*+!-]+)?"
)


def parse_requirements_txt(content: str, manifest_path: str) -> List[DependencyRecord]:
    """Parse requirements.txt file content into DependencyRecord objects."""
    records: List[DependencyRecord] = []
    lines = content.splitlines()

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        # Skip empty lines and full line comments
        if not line or line.startswith("#"):
            continue

        # Strip inline comments
        if " #" in line:
            line = line.split(" #", 1)[0].strip()

        # Skip CLI flags like -r other.txt, -i https://..., -f, --index-url
        if line.startswith(("-r", "-i", "-f", "--")):
            continue

        # Strip environment markers (; python_version >= '3.8')
        if ";" in line:
            line = line.split(";", 1)[0].strip()

        match = REQ_REGEX.match(line)
        if not match:
            continue

        pkg_name = match.group(1)
        operator = match.group(2)
        version_val = match.group(3)

        normalized = normalize_pypi_name(pkg_name)
        resolved_version: Optional[str] = None
        constraint: Optional[str] = None
        status = ResolutionStatus.UNRESOLVED_CONSTRAINT

        if operator and version_val:
            constraint = f"{operator}{version_val}"
            if operator in ("==", "===") and "*" not in version_val:
                resolved_version = version_val
                status = ResolutionStatus.RESOLVED

        records.append(
            DependencyRecord(
                name=pkg_name,
                normalized_name=normalized,
                ecosystem="PyPI",
                version=resolved_version,
                constraint=constraint,
                is_direct=True,
                scope=DependencyScope.PRODUCTION,
                source_manifest=manifest_path,
                declaration_line=idx,
                resolution_status=status,
            )
        )

    return records


def parse_pyproject_toml(content: str, manifest_path: str) -> List[DependencyRecord]:
    """Parse pyproject.toml dependencies (PEP 621 and Poetry styles)."""
    records: List[DependencyRecord] = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return records

    # 1. Standard PEP 621: [project.dependencies]
    project = data.get("project", {})
    if isinstance(project, dict):
        standard_deps = project.get("dependencies", [])
        if isinstance(standard_deps, list):
            for dep_str in standard_deps:
                if isinstance(dep_str, str):
                    parsed = parse_requirements_txt(dep_str, manifest_path)
                    records.extend(parsed)

        # [project.optional-dependencies]
        opt_deps = project.get("optional-dependencies", {})
        if isinstance(opt_deps, dict):
            for group_name, dep_list in opt_deps.items():
                scope = DependencyScope.DEVELOPMENT if "dev" in group_name.lower() or "test" in group_name.lower() else DependencyScope.OPTIONAL
                if isinstance(dep_list, list):
                    for dep_str in dep_list:
                        if isinstance(dep_str, str):
                            for rec in parse_requirements_txt(dep_str, manifest_path):
                                rec.scope = scope
                                records.append(rec)

    # 2. Poetry style: [tool.poetry.dependencies]
    tool = data.get("tool", {})
    if isinstance(tool, dict):
        poetry = tool.get("poetry", {})
        if isinstance(poetry, dict):
            p_deps = poetry.get("dependencies", {})
            if isinstance(p_deps, dict):
                for pkg_name, spec in p_deps.items():
                    if pkg_name.lower() == "python":
                        continue
                    rec = _parse_poetry_dep(pkg_name, spec, manifest_path, DependencyScope.PRODUCTION)
                    if rec:
                        records.append(rec)

            # [tool.poetry.group.<group>.dependencies]
            groups = poetry.get("group", {})
            if isinstance(groups, dict):
                for group_name, group_data in groups.items():
                    if isinstance(group_data, dict):
                        g_deps = group_data.get("dependencies", {})
                        scope = DependencyScope.DEVELOPMENT if "dev" in group_name.lower() or "test" in group_name.lower() else DependencyScope.OPTIONAL
                        if isinstance(g_deps, dict):
                            for pkg_name, spec in g_deps.items():
                                rec = _parse_poetry_dep(pkg_name, spec, manifest_path, scope)
                                if rec:
                                    records.append(rec)

    return records


def _parse_poetry_dep(name: str, spec: any, manifest_path: str, scope: DependencyScope) -> Optional[DependencyRecord]:
    normalized = normalize_pypi_name(name)
    constraint = None
    resolved_version = None
    status = ResolutionStatus.UNRESOLVED_CONSTRAINT

    if isinstance(spec, str):
        constraint = spec
        if spec.startswith("==") and "*" not in spec:
            resolved_version = spec[2:].strip()
            status = ResolutionStatus.RESOLVED
        elif re.match(r"^[0-9]+(\.[0-9]+)*$", spec):
            resolved_version = spec
            status = ResolutionStatus.RESOLVED
    elif isinstance(spec, dict):
        ver = spec.get("version")
        if isinstance(ver, str):
            constraint = ver
            if ver.startswith("==") and "*" not in ver:
                resolved_version = ver[2:].strip()
                status = ResolutionStatus.RESOLVED

    return DependencyRecord(
        name=name,
        normalized_name=normalized,
        ecosystem="PyPI",
        version=resolved_version,
        constraint=constraint,
        is_direct=True,
        scope=scope,
        source_manifest=manifest_path,
        resolution_status=status,
    )


def parse_pipfile_lock(content: str, manifest_path: str) -> List[DependencyRecord]:
    """Parse Pipfile.lock JSON format."""
    records: List[DependencyRecord] = []
    try:
        data = json.loads(content)
    except Exception:
        return records

    sections = [
        ("default", DependencyScope.PRODUCTION),
        ("develop", DependencyScope.DEVELOPMENT),
    ]

    for section_name, scope in sections:
        sec_data = data.get(section_name, {})
        if isinstance(sec_data, dict):
            for pkg_name, info in sec_data.items():
                if not isinstance(info, dict):
                    continue
                version_raw = info.get("version", "")
                resolved_version = None
                status = ResolutionStatus.UNRESOLVED_CONSTRAINT

                if version_raw.startswith("=="):
                    resolved_version = version_raw[2:].strip()
                    status = ResolutionStatus.RESOLVED

                records.append(
                    DependencyRecord(
                        name=pkg_name,
                        normalized_name=normalize_pypi_name(pkg_name),
                        ecosystem="PyPI",
                        version=resolved_version,
                        constraint=version_raw or None,
                        is_direct=True,
                        scope=scope,
                        source_manifest=manifest_path,
                        resolution_status=status,
                    )
                )

    return records


def parse_poetry_lock(content: str, manifest_path: str) -> List[DependencyRecord]:
    """Parse poetry.lock TOML format with exact resolved versions and dependency trees."""
    records: List[DependencyRecord] = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return records

    packages = data.get("package", [])
    if not isinstance(packages, list):
        return records

    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        pkg_name = pkg.get("name")
        version = pkg.get("version")
        if not pkg_name or not version:
            continue

        category = pkg.get("category", "main")
        scope = DependencyScope.DEVELOPMENT if category == "dev" else DependencyScope.PRODUCTION

        # Extract child dependencies declared in this locked package
        child_deps_raw = pkg.get("dependencies", {})
        child_deps: dict[str, str] = {}
        if isinstance(child_deps_raw, dict):
            for child_name, child_spec in child_deps_raw.items():
                if isinstance(child_spec, str):
                    child_deps[normalize_pypi_name(child_name)] = child_spec
                elif isinstance(child_spec, dict) and "version" in child_spec:
                    child_deps[normalize_pypi_name(child_name)] = str(child_spec["version"])

        records.append(
            DependencyRecord(
                name=pkg_name,
                normalized_name=normalize_pypi_name(pkg_name),
                ecosystem="PyPI",
                version=str(version),
                constraint=f"=={version}",
                is_direct=False,  # lockfile contains full resolved tree
                scope=scope,
                source_manifest=manifest_path,
                dependencies=child_deps,
                resolution_status=ResolutionStatus.RESOLVED,
            )
        )

    return records

