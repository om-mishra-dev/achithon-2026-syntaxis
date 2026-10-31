"""Phase F: Evaluation framework public API."""

from auditor.evaluation.models import (
    BenchmarkCase,
    CaseResult,
    DetectionMetrics,
    EvaluationRun,
)
from auditor.evaluation.dataset import (
    load_manifest,
    validate_dataset,
    compute_manifest_hash,
)
from auditor.evaluation.runner import BenchmarkRunner, build_evaluation_run
from auditor.evaluation.metrics import (
    compute_detection_metrics,
    compute_per_category,
    compute_performance_metrics,
    compute_patch_metrics,
)
from auditor.evaluation.report import save_evaluation_json, save_evaluation_markdown

__all__ = [
    "BenchmarkCase",
    "CaseResult",
    "DetectionMetrics",
    "EvaluationRun",
    "load_manifest",
    "validate_dataset",
    "compute_manifest_hash",
    "BenchmarkRunner",
    "build_evaluation_run",
    "compute_detection_metrics",
    "compute_per_category",
    "compute_performance_metrics",
    "compute_patch_metrics",
    "save_evaluation_json",
    "save_evaluation_markdown",
]

