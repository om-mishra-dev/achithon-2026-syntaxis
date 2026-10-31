"""Dependency resolution coordinator: parses discovered manifests and correlates records."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Set

from auditor.core.models import DiscoveredFile
from auditor.core.safety import is_safe_file_for_analysis
from .models import DependencyRecord, ResolutionStatus
from .npm_parser import parse_package_json, parse_package_lock_json
from .python_parser import (
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_pyproject_toml,
    parse_requirements_txt,
)


class ManifestResolver:
    """Dispatches manifests to appropriate parsers and merges direct/resolved declarations."""

    def parse_manifest_file(self, file_info: DiscoveredFile) -> List[DependencyRecord]:
        path = Path(file_info.path)
        is_safe, reason = is_safe_file_for_analysis(path)
        if not is_safe:
            return []

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        fname = path.name.lower()
        rel_path = file_info.relative_path

        if fname == "requirements.txt" or fname.startswith("requirements"):
            return parse_requirements_txt(content, rel_path)
        elif fname == "pyproject.toml":
            return parse_pyproject_toml(content, rel_path)
        elif fname == "pipfile.lock":
            return parse_pipfile_lock(content, rel_path)
        elif fname == "poetry.lock":
            return parse_poetry_lock(content, rel_path)
        elif fname == "package.json":
            return parse_package_json(content, rel_path)
        elif fname == "package-lock.json":
            return parse_package_lock_json(content, rel_path)

        return []

    def resolve_all(self, manifest_files: List[DiscoveredFile]) -> List[DependencyRecord]:
        """Parse all discovered manifests and cross-correlate direct declarations with lockfiles."""
        all_records: List[DependencyRecord] = []
        direct_names_by_ecosystem: Dict[str, Set[str]] = {"pypi": set(), "npm": set()}

        # 1. Parse all manifests
        for mf in manifest_files:
            parsed = self.parse_manifest_file(mf)
            for rec in parsed:
                if rec.is_direct:
                    eco = rec.ecosystem.lower()
                    if eco in direct_names_by_ecosystem:
                        direct_names_by_ecosystem[eco].add(rec.normalized_name)
            all_records.extend(parsed)

        # 2. Correlate lockfile records: if a lockfile record matches a direct declaration in package.json/pyproject.toml, mark is_direct=True
        for rec in all_records:
            eco = rec.ecosystem.lower()
            if not rec.is_direct and eco in direct_names_by_ecosystem:
                if rec.normalized_name in direct_names_by_ecosystem[eco]:
                    rec.is_direct = True

        return all_records

