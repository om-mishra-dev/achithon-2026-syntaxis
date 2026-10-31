"""Safety guards, path traversal prevention, symlink validation, and secret sanitization."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Tuple

# Limits to prevent resource exhaustion / DoS
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_DISCOVERED_FILES = 10_000
MAX_SCAN_TIMEOUT_SECONDS = 300  # 5 minutes

# Common high-entropy and credential patterns for redaction
SECRET_PATTERNS = [
    # AWS Access Key ID
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "[REDACTED_AWS_ACCESS_KEY]"),
    # AWS Secret Key
    (re.compile(r"(?i)\b(aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?)\b"), "[REDACTED_AWS_SECRET]"),
    # GitHub Personal Access Token / Fine-grained token
    (re.compile(r"\b(ghp_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{36,255})\b"), "[REDACTED_GITHUB_TOKEN]"),
    # OpenAI API keys (sk-..., sk-proj-...)
    (re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})\b"), "[REDACTED_OPENAI_KEY]"),
    # Generic API Keys / Bearer Tokens
    (re.compile(r"(?i)\b(api_key|apikey|secret|token)\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}['\"]"), r"\1=[REDACTED_SECRET]"),
    # Private Key blocks
    (re.compile(r"-----BEGIN (?:RSA|OPENSSH|DSA|EC)? ?PRIVATE KEY-----[\s\S]+?-----END (?:RSA|OPENSSH|DSA|EC)? ?PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    # JWT tokens
    (re.compile(r"\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b"), "[REDACTED_JWT_TOKEN]"),
]


def is_safe_subpath(base_dir: str | Path, target_path: str | Path) -> bool:
    """Validate that target_path resolves strictly within base_dir, preventing directory traversal.
    
    Rejects relative jumps (../../) and symlinks escaping the sandbox.
    """
    try:
        base = Path(base_dir).resolve()
        target = Path(target_path).resolve()
        # On Windows or Unix, check if base is in target's parents or equal
        return base == target or base in target.parents
    except (ValueError, RuntimeError, OSError):
        return False


def ensure_safe_subpath(base_dir: str | Path, target_path: str | Path) -> Path:
    """Return the resolved Path if safe, otherwise raise ValueError."""
    if not is_safe_subpath(base_dir, target_path):
        raise ValueError(
            f"Security violation: path '{target_path}' resolves outside allowed base directory '{base_dir}'"
        )
    return Path(target_path).resolve()


def is_safe_file_for_analysis(file_path: str | Path, max_size_bytes: int = MAX_FILE_SIZE_BYTES) -> Tuple[bool, str]:
    """Check if a file is safe and appropriate for static/dependency analysis.
    
    Returns (is_safe, reason).
    """
    path = Path(file_path)
    if not path.exists():
        return False, "File does not exist"
    
    if path.is_symlink():
        try:
            resolved = path.resolve(strict=True)
            if not resolved.exists():
                return False, "Broken symlink"
        except (RuntimeError, OSError):
            return False, "Unresolvable symlink / recursive link"

    if not path.is_file():
        return False, "Not a regular file"

    try:
        stat_res = path.stat()
        if stat_res.st_size > max_size_bytes:
            return False, f"File size ({stat_res.st_size} bytes) exceeds maximum limit ({max_size_bytes} bytes)"
    except OSError as err:
        return False, f"Cannot access file stat: {err}"

    return True, "OK"


def redact_secrets(text: str) -> str:
    """Scrub sensitive credentials, tokens, and private keys from strings."""
    if not text:
        return text
    sanitized = text
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized

