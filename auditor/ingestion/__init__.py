"""Ingestion modules for handling local directories and Git repositories."""

from .base import BaseIngester, IngestionResult
from .local import LocalIngester
from .git import GitIngester
from .factory import get_ingester

__all__ = ["BaseIngester", "IngestionResult", "LocalIngester", "GitIngester", "get_ingester"]

