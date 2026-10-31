"""Base ingestion interface and result container."""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, Optional


class IngestionResult:
    """Represents an ingested repository ready for scanning."""

    def __init__(
        self,
        working_dir: Path,
        original_target: str,
        is_temporary: bool = False,
        cleanup_fn: Optional[Callable[[], None]] = None,
    ):
        self.working_dir = working_dir.resolve()
        self.original_target = original_target
        self.is_temporary = is_temporary
        self.cleanup_fn = cleanup_fn
        self._cleaned = False

    def cleanup(self) -> None:
        """Clean up any temporary directory resources."""
        if self._cleaned:
            return
        if self.cleanup_fn:
            try:
                self.cleanup_fn()
            except Exception:
                pass
        elif self.is_temporary and self.working_dir.exists():
            try:
                shutil.rmtree(self.working_dir, ignore_errors=True)
            except Exception:
                pass
        self._cleaned = True

    def __enter__(self) -> IngestionResult:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()


class BaseIngester(ABC):
    """Abstract ingester interface."""

    @abstractmethod
    def ingest(self, target: str) -> IngestionResult:
        """Ingest the target (local path or URL) and return an IngestionResult."""
        pass

