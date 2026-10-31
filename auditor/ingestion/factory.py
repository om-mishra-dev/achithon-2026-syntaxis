"""Ingester factory to select the appropriate ingester."""

from __future__ import annotations

import re
from .base import BaseIngester
from .git import GitIngester
from .local import LocalIngester

GIT_URL_PREFIXES = ("https://", "http://", "git://", "ssh://", "git@")


def get_ingester(target: str) -> BaseIngester:
    """Determine whether target is a Git URL or local directory and return an ingester."""
    target_clean = target.strip()
    if any(target_clean.startswith(prefix) for prefix in GIT_URL_PREFIXES) or target_clean.endswith(".git"):
        return GitIngester()
    return LocalIngester()

