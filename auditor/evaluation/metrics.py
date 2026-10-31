"""Compute detection and performance metrics from benchmark results."""

from __future__ import annotations

import statistics
from typing import Dict, List

from auditor.evaluation.models import CaseResult, DetectionMetrics


def compute_detection_metrics(results: List[CaseResult]) -> DetectionMetrics:
    """Aggregate TP/FP/TN/FN from a list of case results and compute derived metrics."""
    m = DetectionMetrics()
    for r in results:
        if r.status == "tp":
            m.tp += 1
        elif r.status == "fp":
            m.fp += 1
        elif r.status == "tn":
            m.tn += 1
        elif r.status == "fn":
            m.fn += 1
        elif r.status == "error":
            m.errors += 1
        elif r.status == "ambiguous":
            m.ambiguous += 1

    m.supported = m.tp + m.fp + m.tn + m.fn
    m.unsupported = 0  # Reserved for future extension
    return m.compute()


def compute_per_category(results: List[CaseResult]) -> Dict[str, DetectionMetrics]:
    """Compute per-category detection metrics."""
    by_cat: Dict[str, List[CaseResult]] = {}
    for r in results:
        by_cat.setdefault(r.category, []).append(r)
    return {cat: compute_detection_metrics(rs) for cat, rs in by_cat.items()}


def compute_performance_metrics(results: List[CaseResult]) -> Dict[str, object]:
    """Compute timing statistics over the completed cases."""
    durations = [r.duration_seconds for r in results if r.status != "error"]
    if not durations:
        return {
            "total_cases": len(results),
            "min_seconds": None,
            "max_seconds": None,
            "mean_seconds": None,
            "median_seconds": None,
            "total_seconds": None,
        }
    return {
        "total_cases": len(results),
        "min_seconds": round(min(durations), 4),
        "max_seconds": round(max(durations), 4),
        "mean_seconds": round(statistics.mean(durations), 4),
        "median_seconds": round(statistics.median(durations), 4),
        "total_seconds": round(sum(durations), 4),
    }


def compute_patch_metrics(patch_results: List[Dict]) -> Dict[str, object]:
    """Compute patch generation and validation statistics."""
    if not patch_results:
        return {
            "total": 0,
            "generated": 0,
            "validated": 0,
            "failed_validation": 0,
            "requires_review": 0,
            "unsupported": 0,
        }
    total = len(patch_results)
    generated = sum(1 for r in patch_results if r.get("generated"))
    validated = sum(1 for r in patch_results if r.get("validated"))
    failed = sum(1 for r in patch_results if r.get("validation_failed"))
    review = sum(1 for r in patch_results if r.get("requires_review"))
    unsupported = sum(1 for r in patch_results if r.get("unsupported"))
    return {
        "total": total,
        "generated": generated,
        "validated": validated,
        "failed_validation": failed,
        "requires_review": review,
        "unsupported": unsupported,
    }

