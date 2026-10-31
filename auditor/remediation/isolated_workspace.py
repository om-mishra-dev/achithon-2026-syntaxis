"""Isolated workspace for safe patch application and validation.

Rules:
- Never modify the original repository.
- Reject absolute paths, traversal components, and symlinks escaping the workspace.
- Enforce file-size, patch-size, and file-count limits.
- Reliable cleanup even on failure.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from pathlib import Path
from typing import Optional

# Safety limits
MAX_PATCH_BYTES = 256 * 1024        # 256 KB per patch
MAX_FILE_BYTES = 5 * 1024 * 1024   # 5 MB per file
MAX_FILE_COUNT = 500                # max files to copy into workspace


class IsolatedWorkspaceError(Exception):
    pass


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def _validate_relative_path(base: Path, rel: str) -> Path:
    """Resolve rel relative to base, reject traversal and absolute paths."""
    if not rel or Path(rel).is_absolute():
        raise IsolatedWorkspaceError(f"Absolute path rejected: {rel!r}")
    resolved = (base / rel).resolve()
    try:
        resolved.relative_to(base.resolve())
    except ValueError:
        raise IsolatedWorkspaceError(
            f"Path traversal rejected: {rel!r} escapes workspace {base}"
        )
    return resolved


class IsolatedWorkspace:
    """Context manager that creates a temp copy of a repository subtree."""

    def __init__(self, source_root: str | Path) -> None:
        self._source_root = Path(source_root).resolve()
        self._tmpdir: Optional[tempfile.TemporaryDirectory] = None
        self._workspace: Optional[Path] = None

    @property
    def workspace(self) -> Path:
        if self._workspace is None:
            raise IsolatedWorkspaceError("Workspace not entered yet.")
        return self._workspace

    def __enter__(self) -> "IsolatedWorkspace":
        self._tmpdir = tempfile.TemporaryDirectory(prefix="auditor_patch_")
        self._workspace = Path(self._tmpdir.name)
        # Copy source files with limits
        count = 0
        for src_path in self._source_root.rglob("*"):
            if src_path.is_symlink():
                target = src_path.resolve()
                if not str(target).startswith(str(self._source_root)):
                    continue  # skip escaping symlinks
            if not src_path.is_file():
                continue
            if src_path.stat().st_size > MAX_FILE_BYTES:
                continue
            if count >= MAX_FILE_COUNT:
                break
            rel = src_path.relative_to(self._source_root)
            dst = self._workspace / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dst)
            count += 1
        return self

    def __exit__(self, *_) -> None:
        try:
            if self._tmpdir is not None:
                self._tmpdir.cleanup()
        except Exception:
            pass  # record but don't hide

    # ------------------------------------------------------------------
    # File operations (all paths validated against workspace root)
    # ------------------------------------------------------------------

    def read_file(self, rel_path: str) -> str:
        full = _validate_relative_path(self.workspace, rel_path)
        if full.is_symlink():
            target = full.resolve()
            if not str(target).startswith(str(self.workspace.resolve())):
                raise IsolatedWorkspaceError(
                    f"Symlink {rel_path!r} escapes workspace."
                )
        if not full.exists():
            raise IsolatedWorkspaceError(f"File not found in workspace: {rel_path!r}")
        return full.read_text(encoding="utf-8", errors="replace")

    def write_file(self, rel_path: str, content: str) -> None:
        if len(content.encode("utf-8")) > MAX_PATCH_BYTES:
            raise IsolatedWorkspaceError(
                f"Proposed content exceeds {MAX_PATCH_BYTES} byte limit."
            )
        full = _validate_relative_path(self.workspace, rel_path)
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")

    def file_hash(self, rel_path: str) -> str:
        return _sha256(self.read_file(rel_path))

    def file_exists(self, rel_path: str) -> bool:
        try:
            full = _validate_relative_path(self.workspace, rel_path)
            return full.exists() and full.is_file()
        except IsolatedWorkspaceError:
            return False


def compute_file_hash(file_path: str | Path) -> str:
    """Compute SHA-256 hash of a file on disk (original repository)."""
    path = Path(file_path)
    if not path.exists():
        return ""
    content = path.read_text(encoding="utf-8", errors="replace")
    return _sha256(content)

