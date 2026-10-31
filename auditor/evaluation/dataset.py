"""Load, validate, and hash benchmark dataset manifests."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import List, Tuple

from auditor.evaluation.models import BenchmarkCase

_ALLOWED_LABELS = {"vulnerable", "safe", "ambiguous"}


def load_manifest(path: str | Path) -> Tuple[List[BenchmarkCase], str, str]:
    """
    Load and parse a benchmark manifest JSON file.

    Returns:
        (cases, dataset_version, dataset_id)

    Raises:
        FileNotFoundError: if path does not exist
        ValueError: if the manifest is malformed
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Manifest not found: {path}")

    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)

    version = data.get("version", "unknown")
    dataset_id = data.get("dataset_id", "unknown")

    raw_cases = data.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError("Manifest must contain a 'cases' list.")

    cases: List[BenchmarkCase] = []
    for i, item in enumerate(raw_cases):
        if not isinstance(item, dict):
            raise ValueError(f"Case at index {i} must be a JSON object.")
        try:
            case = BenchmarkCase(**item)
        except Exception as exc:
            raise ValueError(f"Case at index {i} is invalid: {exc}") from exc
        cases.append(case)

    return cases, version, dataset_id


def validate_dataset(
    cases: List[BenchmarkCase],
    benchmark_root: str | Path,
) -> List[str]:
    """
    Validate that benchmark cases meet safety and consistency requirements.

    Returns:
        List of error messages (empty = valid).
    """
    benchmark_root = Path(benchmark_root).resolve()
    errors: List[str] = []
    seen_ids: set[str] = set()

    for case in cases:
        # Duplicate IDs
        if case.id in seen_ids:
            errors.append(f"Duplicate case ID: {case.id!r}")
        seen_ids.add(case.id)

        # Invalid label
        if case.label not in _ALLOWED_LABELS:
            errors.append(
                f"Case {case.id!r}: label {case.label!r} not in {_ALLOWED_LABELS}"
            )

        # Fixture path traversal safety
        fixture_path = (benchmark_root / case.fixture).resolve()
        try:
            fixture_path.relative_to(benchmark_root)
        except ValueError:
            errors.append(
                f"Case {case.id!r}: fixture path escapes benchmark root: {case.fixture!r}"
            )
            continue  # Skip existence check for traversal paths

        if not fixture_path.exists():
            errors.append(
                f"Case {case.id!r}: fixture not found: {case.fixture!r}"
            )

    return errors


def compute_manifest_hash(path: str | Path) -> str:
    """Compute a SHA-256 hex digest of the manifest file content."""
    path = Path(path)
    content = path.read_bytes()
    return hashlib.sha256(content).hexdigest()

