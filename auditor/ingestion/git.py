"""Safe Git repository ingester with shallow cloning and strict sandboxing."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .base import BaseIngester, IngestionResult

# Safe URL format check (handles https://, http://, git://, ssh://, git@)
SAFE_GIT_URL_REGEX = re.compile(
    r"^(https?://|git://|ssh://|git@)(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9_.-]+(?::[0-9]+)?(?:[:/][A-Za-z0-9_.~-]+)+/?(?:\.git)?$"
)
DISALLOWED_SHELL_CHARS = re.compile(r"[;&|`$<>\r\n]")


class GitIngester(BaseIngester):
    """Safely clones a remote Git repository into a temporary directory."""

    def __init__(self, clone_timeout_seconds: int = 60):
        self.clone_timeout_seconds = clone_timeout_seconds

    def validate_url(self, url: str) -> bool:
        """Validate that the git URL is well-formed and contains no shell metacharacters."""
        if not url or DISALLOWED_SHELL_CHARS.search(url):
            return False
        return bool(SAFE_GIT_URL_REGEX.match(url.strip()))

    def ingest(self, target: str) -> IngestionResult:
        clean_url = target.strip()
        if not self.validate_url(clean_url):
            raise ValueError(f"Invalid or unsafe Git repository URL format: '{target}'")

        temp_dir = tempfile.mkdtemp(prefix="auditor_repo_")
        target_path = Path(temp_dir)

        try:
            # Execute shallow clone with depth 1 without shell=True
            cmd = [
                "git",
                "clone",
                "--depth",
                "1",
                "--single-branch",
                "--config",
                "core.autocrlf=false",
                clean_url,
                str(target_path),
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.clone_timeout_seconds,
                check=False,
            )

            if result.returncode != 0:
                shutil.rmtree(target_path, ignore_errors=True)
                error_msg = result.stderr.strip() or result.stdout.strip() or "Unknown clone failure"
                raise RuntimeError(f"Git clone failed (exit code {result.returncode}): {error_msg}")

            def cleanup():
                shutil.rmtree(target_path, ignore_errors=True)

            return IngestionResult(
                working_dir=target_path,
                original_target=clean_url,
                is_temporary=True,
                cleanup_fn=cleanup,
            )

        except subprocess.TimeoutExpired:
            shutil.rmtree(target_path, ignore_errors=True)
            raise TimeoutError(
                f"Git clone timed out after {self.clone_timeout_seconds} seconds for target: {clean_url}"
            )
        except Exception:
            shutil.rmtree(target_path, ignore_errors=True)
            raise
