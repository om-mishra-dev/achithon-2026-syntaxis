"""Data models for the Phase F evaluation framework."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class BenchmarkCase(BaseModel):
    """Represents a single ground-truth benchmark test case."""
    id: str
    category: str
    label: Literal["vulnerable", "safe", "ambiguous"]
    fixture: str
    description: str
    rationale: str
    expected_cwe: Optional[str] = None
    expected_package: Optional[str] = None
    expected_advisory_id: Optional[str] = None
    expected_fixed_version: Optional[str] = None
    expected_strategy: Optional[str] = None
    expected_finding_type: Optional[str] = None
    expected_line: Optional[int] = None


class CaseResult(BaseModel):
    """Result of running a single benchmark case through the scanner."""
    case_id: str
    label: str
    category: str
    findings_count: int = 0
    finding_ids: List[str] = Field(default_factory=list)
    expected_cwe: Optional[str] = None
    matched_cwe: bool = False
    expected_line: Optional[int] = None
    actual_lines: List[int] = Field(default_factory=list)
    location_correct: bool = False
    duration_seconds: float = 0.0
    # tp=true positive, fp=false positive, tn=true negative, fn=false negative,
    # error=scanner error, ambiguous=ambiguous label (excluded from binary metrics)
    status: str = "fn"
    error: Optional[str] = None


class DetectionMetrics(BaseModel):
    """Binary classification metrics for detection quality."""
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None
    accuracy: Optional[float] = None
    supported: int = 0
    unsupported: int = 0
    ambiguous: int = 0
    errors: int = 0

    def compute(self) -> "DetectionMetrics":
        """Compute precision, recall, F1, and accuracy from TP/FP/TN/FN counts."""
        if self.tp + self.fp > 0:
            self.precision = round(self.tp / (self.tp + self.fp), 4)
        else:
            self.precision = None

        if self.tp + self.fn > 0:
            self.recall = round(self.tp / (self.tp + self.fn), 4)
        else:
            self.recall = None

        if self.precision is not None and self.recall is not None:
            p, r = self.precision, self.recall
            if p + r > 0:
                self.f1 = round(2 * p * r / (p + r), 4)
            else:
                self.f1 = 0.0
        else:
            self.f1 = None

        total = self.tp + self.fp + self.tn + self.fn
        if total > 0:
            self.accuracy = round((self.tp + self.tn) / total, 4)
        else:
            self.accuracy = None

        return self


class EvaluationRun(BaseModel):
    """Complete record of a benchmark evaluation run."""
    run_id: str
    timestamp: str
    dataset_version: str
    dataset_id: str
    dataset_hash: str
    offline: bool = True
    no_llm: bool = True
    cases_total: int = 0
    cases_completed: int = 0
    overall_metrics: DetectionMetrics = Field(default_factory=DetectionMetrics)
    per_category: Dict[str, DetectionMetrics] = Field(default_factory=dict)
    case_results: List[CaseResult] = Field(default_factory=list)
    patch_metrics: Dict[str, Any] = Field(default_factory=dict)
    agent_metrics: Dict[str, Any] = Field(default_factory=dict)
    performance: Dict[str, Any] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)
    summary: str = ""

