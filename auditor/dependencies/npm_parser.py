"""Parsers for JavaScript/TypeScript dependency manifests: package.json and package-lock.json."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import (
    DependencyRecord,
    DependencyScope,
    ResolutionStatus,
    normalize_npm_name,
)


def parse_package_json(content: str, manifest_path: str) -> List[DependencyRecord]:
    """Parse package.json declared dependencies."""
    records: List[DependencyRecord] = []
    try:
        data = json.loads(content)
    except Exception:
        return records

    scope_sections = [
        ("dependencies", DependencyScope.PRODUCTION),
        ("devDependencies", DependencyScope.DEVELOPMENT),
        ("peerDependencies", DependencyScope.PEER),
        ("optionalDependencies", DependencyScope.OPTIONAL),
    ]

    for section_name, scope in scope_sections:
        deps = data.get(section_name, {})
        if isinstance(deps, dict):
            for pkg_name, constraint_val in deps.items():
                if not isinstance(constraint_val, str):
                    continue

                normalized = normalize_npm_name(pkg_name)
                # Check if exact pin without ranges (^, ~, >, <, *, x)
                resolved_version: Optional[str] = None
                status = ResolutionStatus.UNRESOLVED_CONSTRAINT

                if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9._-]+)?$", constraint_val.strip()):
                    resolved_version = constraint_val.strip()
                    status = ResolutionStatus.RESOLVED

                records.append(
                    DependencyRecord(
                        name=pkg_name,
                        normalized_name=normalized,
                        ecosystem="npm",
                        version=resolved_version,
                        constraint=constraint_val.strip(),
                        is_direct=True,
                        scope=scope,
                        source_manifest=manifest_path,
                        resolution_status=status,
                    )
                )

    return records


def parse_package_lock_json(content: str, manifest_path: str) -> List[DependencyRecord]:
    """Parse package-lock.json (supporting v1, v2, and v3 schemas)."""
    records: List[DependencyRecord] = []
    try:
        data = json.loads(content)
    except Exception:
        return records

    lockfile_ver = data.get("lockfileVersion", 1)

    # v2 and v3 format: "packages" key
    if "packages" in data and isinstance(data["packages"], dict):
        for pkg_path, pkg_info in data["packages"].items():
            if not isinstance(pkg_info, dict):
                continue
            # Skip root application package ("")
            if pkg_path == "":
                continue

            # Extract clean package name from node_modules path
            pkg_name = pkg_info.get("name")
            if not pkg_name:
                # Fallback: extract from path (e.g. "node_modules/@scope/pkg" -> "@scope/pkg")
                if "node_modules/" in pkg_path:
                    pkg_name = pkg_path.split("node_modules/")[-1]
                else:
                    pkg_name = pkg_path

            version = pkg_info.get("version")
            if not version:
                continue

            is_dev = pkg_info.get("dev", False)
            scope = DependencyScope.DEVELOPMENT if is_dev else DependencyScope.PRODUCTION

            # Extract child dependencies
            child_deps_raw = pkg_info.get("dependencies", {})
            child_deps: Dict[str, str] = {}
            if isinstance(child_deps_raw, dict):
                for k, v in child_deps_raw.items():
                    if isinstance(v, str):
                        child_deps[normalize_npm_name(k)] = v

            records.append(
                DependencyRecord(
                    name=pkg_name,
                    normalized_name=normalize_npm_name(pkg_name),
                    ecosystem="npm",
                    version=str(version),
                    constraint=f"=={version}",
                    is_direct=False,  # lockfile captures entire tree
                    scope=scope,
                    source_manifest=manifest_path,
                    dependencies=child_deps,
                    resolution_status=ResolutionStatus.RESOLVED,
                )
            )

    # v1 fallback: "dependencies" key
    elif "dependencies" in data and isinstance(data["dependencies"], dict):
        _parse_v1_dependencies(data["dependencies"], manifest_path, records)

    return records


def _parse_v1_dependencies(
    deps_dict: Dict[str, Any],
    manifest_path: str,
    records: List[DependencyRecord],
    parent_name: Optional[str] = None,
) -> None:
    for pkg_name, info in deps_dict.items():
        if not isinstance(info, dict):
            continue
        version = info.get("version")
        if not version:
            continue

        is_dev = info.get("dev", False)
        scope = DependencyScope.DEVELOPMENT if is_dev else DependencyScope.PRODUCTION

        child_deps_raw = info.get("requires", {})
        child_deps: Dict[str, str] = {}
        if isinstance(child_deps_raw, dict):
            for k, v in child_deps_raw.items():
                if isinstance(v, str):
                    child_deps[normalize_npm_name(k)] = v

        records.append(
            DependencyRecord(
                name=pkg_name,
                normalized_name=normalize_npm_name(pkg_name),
                ecosystem="npm",
                version=str(version),
                constraint=f"=={version}",
                is_direct=parent_name is None,
                scope=scope,
                source_manifest=manifest_path,
                dependencies=child_deps,
                resolution_status=ResolutionStatus.RESOLVED,
                parent_package=parent_name,
            )
        )

        # Recursively parse nested dependencies
        nested = info.get("dependencies")
        if isinstance(nested, dict):
            _parse_v1_dependencies(nested, manifest_path, records, parent_name=pkg_name)

