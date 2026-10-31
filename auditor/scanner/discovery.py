"""File and repository discovery service with language classification and manifest detection."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Tuple

from auditor.core.models import DiscoveredFile
from auditor.core.safety import (
    MAX_DISCOVERED_FILES,
    MAX_FILE_SIZE_BYTES,
    is_safe_file_for_analysis,
    is_safe_subpath,
)

# Directories to skip
DEFAULT_IGNORE_DIRS: Set[str] = {
    ".git",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    "env",
    ".tox",
    "dist",
    "build",
    ".idea",
    ".vscode",
    ".mypy_cache",
    ".ruff_cache",
    "coverage",
    ".next",
    ".nuget",
    ".gradle",
    "target",
    "bin",
    "obj",
}

# Supported file extensions to language
LANGUAGE_EXTENSIONS: Dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".h": "c",
    ".hpp": "cpp",
}

# Known dependency manifest files
MANIFEST_FILENAMES: Dict[str, str] = {
    "requirements.txt": "python_requirements",
    "Pipfile": "python_pipfile",
    "Pipfile.lock": "python_pipfile_lock",
    "poetry.lock": "python_poetry_lock",
    "pyproject.toml": "python_pyproject",
    "setup.py": "python_setup",
    "package.json": "npm_package",
    "package-lock.json": "npm_package_lock",
    "yarn.lock": "npm_yarn_lock",
    "pnpm-lock.yaml": "npm_pnpm_lock",
    "go.mod": "go_mod",
    "go.sum": "go_sum",
    "Cargo.toml": "cargo_toml",
    "Cargo.lock": "cargo_lock",
}

# Extensions to skip (binary/media)
BINARY_EXTENSIONS: Set[str] = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".zip", ".tar", ".gz",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".mp4", ".mp3", ".wav",
    ".pyc", ".pyo", ".pyd", ".wasm", ".class", ".jar", ".war"
}


@dataclass
class DiscoveryResult:
    base_dir: Path
    files: List[DiscoveredFile] = field(default_factory=list)
    manifest_files: List[DiscoveredFile] = field(default_factory=list)
    source_files: List[DiscoveredFile] = field(default_factory=list)
    language_counts: Dict[str, int] = field(default_factory=dict)
    skipped_count: int = 0
    total_discovered: int = 0


class FileDiscoveryService:
    """Discovers source files, classifies languages, and identifies dependency manifests."""

    def __init__(
        self,
        ignore_dirs: Set[str] | None = None,
        max_files: int = MAX_DISCOVERED_FILES,
        max_file_size_bytes: int = MAX_FILE_SIZE_BYTES,
    ):
        self.ignore_dirs = ignore_dirs or DEFAULT_IGNORE_DIRS
        self.max_files = max_files
        self.max_file_size_bytes = max_file_size_bytes

    def discover(self, root_dir: Path | str) -> DiscoveryResult:
        base_path = Path(root_dir).resolve()
        result = DiscoveryResult(base_dir=base_path)

        for dirpath, dirnames, filenames in os.walk(base_path):
            # Prune ignored directories in-place to avoid descending
            dirnames[:] = [
                d for d in dirnames
                if d not in self.ignore_dirs and not d.startswith(".")
            ]

            current_dir = Path(dirpath)
            # Ensure current directory does not escape root via symlinks
            if not is_safe_subpath(base_path, current_dir):
                continue

            for fname in filenames:
                if result.total_discovered >= self.max_files:
                    result.skipped_count += 1
                    continue

                file_path = current_dir / fname
                result.total_discovered += 1

                # Basic safety & size check
                is_safe, reason = is_safe_file_for_analysis(file_path, self.max_file_size_bytes)
                if not is_safe:
                    result.skipped_count += 1
                    continue

                ext = file_path.suffix.lower()
                if ext in BINARY_EXTENSIONS:
                    result.skipped_count += 1
                    continue

                try:
                    rel_path = str(file_path.relative_to(base_path))
                except ValueError:
                    result.skipped_count += 1
                    continue

                size = file_path.stat().st_size
                is_manifest = fname.lower() in MANIFEST_FILENAMES or fname.lower().startswith("requirements")
                manifest_type = MANIFEST_FILENAMES.get(fname.lower())
                if is_manifest and not manifest_type and "requirements" in fname.lower():
                    manifest_type = "python_requirements"

                lang = LANGUAGE_EXTENSIONS.get(ext)

                discovered = DiscoveredFile(
                    path=str(file_path),
                    relative_path=rel_path,
                    language=lang,
                    size_bytes=size,
                    is_manifest=is_manifest,
                    manifest_type=manifest_type,
                )

                result.files.append(discovered)

                if is_manifest:
                    result.manifest_files.append(discovered)

                if lang:
                    result.source_files.append(discovered)
                    result.language_counts[lang] = result.language_counts.get(lang, 0) + 1

        return result

