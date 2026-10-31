"""Local directory ingester."""

from __future__ import annotations

import os
from pathlib import Path

from auditor.core.safety import is_safe_subpath
from .base import BaseIngester, IngestionResult


class LocalIngester(BaseIngester):
    """Ingests and validates a local codebase directory."""

    def ingest(self, target: str) -> IngestionResult:
        path = Path(target).expanduser().resolve()

        if not path.exists():
            raise FileNotFoundError(f"Target directory does not exist: {target}")

        if not path.is_dir():
            raise NotADirectoryError(f"Target path is not a directory: {target}")

        # Check permission to read
        if not os.access(path, os.R_OK):
            raise PermissionError(f"Target directory is not readable: {target}")

        return IngestionResult(
            working_dir=path,
            original_target=str(target),
            is_temporary=False,
            cleanup_fn=None,
        )

