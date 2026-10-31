"""Benchmark runner: executes scanner on each fixture and classifies results."""

from __future__ import annotations

import json
import shutil
import tempfile
import time
from pathlib import Path
from typing import List, Optional
from unittest.mock import patch as mock_patch, MagicMock

from auditor.core.config import ScanConfig
from auditor.core.models import FindingType
from auditor.evaluation.models import BenchmarkCase, CaseResult, EvaluationRun, DetectionMetrics
from auditor.evaluation.metrics import (
    compute_detection_metrics,
    compute_per_category,
    compute_performance_metrics,
    compute_patch_metrics,
)


def _load_mock_advisories() -> List[dict]:
    """Load mock OSV advisory records from the benchmark fixture directory."""
    mock_path = Path("benchmarks/fixtures/deps/mock_advisories.json")
    if mock_path.exists():
        return json.loads(mock_path.read_text(encoding="utf-8"))
    return []


def _run_scan_on_fixture(
    fixture_path: Path,
    offline: bool = True,
    no_llm: bool = True,
) -> List[dict]:
    """
    Copy a single fixture into a temp directory and run the scanner over it.

    Returns a list of finding dicts from the scan result.
    """
    from auditor.cli import run_scan

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        dest = tmpdir_path / fixture_path.name
        shutil.copy2(fixture_path, dest)

        out_path = tmpdir_path / "scan_result.json"
        config = ScanConfig(
            target=str(tmpdir_path),
            output_formats=["json"],
            output_path=str(out_path),
            offline_mode=offline,
            include_sast=True,
            include_deps=True,
            include_agents=False,  # Skip agents for speed
            enable_llm=not no_llm,
            verbose=False,
        )

        try:
            run_scan(config)
        except Exception:
            return []

        if not out_path.exists():
            return []
        try:
            data = json.loads(out_path.read_text(encoding="utf-8"))
            return data.get("findings", [])
        except Exception:
            return []


def _run_dep_scan_with_mock(
    fixture_path: Path,
    offline: bool = True,
    no_llm: bool = True,
) -> List[dict]:
    """
    Run a dependency scan on a manifest fixture with mocked OSV responses.
    """
    from auditor.cli import run_scan
    mock_advisories = _load_mock_advisories()

    def _mock_osv_query(self, package_queries):
        """Return mock OSVQueryResult objects for known vulnerable packages."""
        from auditor.advisories.osv_client import OSVQueryResult, AdvisoryStatus
        results = []
        for item in package_queries:
            if isinstance(item, (tuple, list)) and len(item) >= 3:
                ecosystem, name, version = item[0], item[1], item[2]
            else:
                ecosystem, name, version = "PyPI", str(item), ""

            matched = False
            advisories = []
            for adv in mock_advisories:
                for affected in adv.get("affected", []):
                    pkg_info = affected.get("package", {})
                    if pkg_info.get("name", "").lower() != name.lower():
                        continue
                    for rng in affected.get("ranges", []):
                        events = rng.get("events", [])
                        fixed = None
                        for evt in events:
                            if "fixed" in evt:
                                fixed = evt["fixed"]
                        if fixed and version and _version_lt(version, fixed):
                            advisories.append(adv)
                            matched = True

            results.append(OSVQueryResult(
                ecosystem=ecosystem if isinstance(ecosystem, str) else "PyPI",
                package_name=name,
                version=version,
                status=AdvisoryStatus.MATCHED if matched else AdvisoryStatus.NO_MATCH,
                advisories=advisories,
            ))
        return results

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        dest = tmpdir_path / fixture_path.name
        shutil.copy2(fixture_path, dest)
        out_path = tmpdir_path / "scan_result.json"

        config = ScanConfig(
            target=str(tmpdir_path),
            output_formats=["json"],
            output_path=str(out_path),
            offline_mode=offline,
            include_sast=True,
            include_deps=True,
            include_agents=False,
            enable_llm=not no_llm,
            verbose=False,
        )

        from auditor.advisories import osv_client as osv_module
        with mock_patch.object(osv_module.OSVClient, "query_batch", _mock_osv_query):
            try:
                run_scan(config)
            except Exception:
                return []

        if not out_path.exists():
            return []
        try:
            data = json.loads(out_path.read_text(encoding="utf-8"))
            return data.get("findings", [])
        except Exception:
            return []


def _version_lt(v1: str, v2: str) -> bool:
    """
    Simple semantic version comparison: returns True if v1 < v2.
    Falls back to lexicographic comparison on non-numeric parts.
    """
    def _parts(v: str):
        parts = []
        for seg in v.split("."):
            try:
                parts.append(int(seg))
            except ValueError:
                parts.append(seg)
        return parts

    try:
        return _parts(v1) < _parts(v2)
    except TypeError:
        return str(v1) < str(v2)


def _classify_result(case: BenchmarkCase, findings: List[dict]) -> CaseResult:
    """Classify scanner output against ground-truth label."""
    finding_ids = [f.get("id", "") for f in findings]
    actual_cwes = {f.get("cwe_id") for f in findings if f.get("cwe_id")}
    actual_lines = [
        f["location"]["line"]
        for f in findings
        if isinstance(f.get("location"), dict) and "line" in f["location"]
    ]
    findings_count = len(findings)

    matched_cwe = (
        case.expected_cwe is not None and case.expected_cwe in actual_cwes
    )
    location_correct = (
        case.expected_line is None
        or case.expected_line in actual_lines
    )

    # For dep cases, also match on package name and advisory id
    if case.category == "deps":
        matched_pkg = case.expected_package is None or any(
            f.get("package_name", "").lower() == case.expected_package.lower()
            for f in findings
        )
        matched_adv = case.expected_advisory_id is None or any(
            case.expected_advisory_id in (f.get("cve_id", "") or "")
            or case.expected_advisory_id in str(f.get("title", ""))
            for f in findings
        )
        detected = findings_count > 0 and matched_pkg
    else:
        detected = findings_count > 0
        if case.expected_cwe:
            detected = matched_cwe

    # Determine outcome
    if case.label == "ambiguous":
        status = "ambiguous"
    elif case.label == "vulnerable":
        status = "tp" if detected else "fn"
    else:  # safe
        status = "tn" if not detected else "fp"

    return CaseResult(
        case_id=case.id,
        label=case.label,
        category=case.category,
        findings_count=findings_count,
        finding_ids=finding_ids,
        expected_cwe=case.expected_cwe,
        matched_cwe=matched_cwe,
        expected_line=case.expected_line,
        actual_lines=actual_lines,
        location_correct=location_correct,
        status=status,
    )


class BenchmarkRunner:
    """Runs benchmark cases through the scanner and classifies results."""

    def __init__(
        self,
        repo_root: str | Path,
        offline: bool = True,
        no_llm: bool = True,
        category_filter: Optional[str] = None,
        case_id_filter: Optional[str] = None,
    ):
        self.repo_root = Path(repo_root).resolve()
        self.offline = offline
        self.no_llm = no_llm
        self.category_filter = category_filter
        self.case_id_filter = case_id_filter

    def run_case(self, case: BenchmarkCase) -> CaseResult:
        """Run a single benchmark case through the scanner."""
        fixture_path = (self.repo_root / case.fixture).resolve()
        start = time.monotonic()
        findings = []

        try:
            if not fixture_path.exists():
                return CaseResult(
                    case_id=case.id,
                    label=case.label,
                    category=case.category,
                    status="error",
                    error=f"Fixture not found: {case.fixture}",
                    duration_seconds=0.0,
                )

            is_dep_manifest = fixture_path.suffix in {".txt", ".json"} and case.category == "deps"

            if is_dep_manifest:
                findings = _run_dep_scan_with_mock(
                    fixture_path,
                    offline=self.offline,
                    no_llm=self.no_llm,
                )
            else:
                findings = _run_scan_on_fixture(
                    fixture_path,
                    offline=self.offline,
                    no_llm=self.no_llm,
                )
        except Exception as exc:
            elapsed = time.monotonic() - start
            return CaseResult(
                case_id=case.id,
                label=case.label,
                category=case.category,
                status="error",
                error=str(exc),
                duration_seconds=round(elapsed, 4),
            )

        elapsed = time.monotonic() - start
        result = _classify_result(case, findings)
        result.duration_seconds = round(elapsed, 4)
        return result

    def run_all(self, cases: List[BenchmarkCase]) -> List[CaseResult]:
        """Run all matching benchmark cases."""
        results = []
        for case in cases:
            if self.category_filter and case.category != self.category_filter:
                continue
            if self.case_id_filter and case.id != self.case_id_filter:
                continue
            result = self.run_case(case)
            results.append(result)
        return results


def build_evaluation_run(
    cases: List[BenchmarkCase],
    results: List[CaseResult],
    run_id: str,
    timestamp: str,
    dataset_version: str,
    dataset_id: str,
    dataset_hash: str,
    offline: bool = True,
    no_llm: bool = True,
) -> EvaluationRun:
    """Assemble a complete EvaluationRun from cases and results."""
    overall = compute_detection_metrics(results)
    per_cat = compute_per_category(results)
    perf = compute_performance_metrics(results)

    # Count cases by status for summary
    status_counts = {}
    for r in results:
        status_counts[r.status] = status_counts.get(r.status, 0) + 1

    tp = status_counts.get("tp", 0)
    tn = status_counts.get("tn", 0)
    fn = status_counts.get("fn", 0)
    fp = status_counts.get("fp", 0)
    errs = status_counts.get("error", 0)
    amb = status_counts.get("ambiguous", 0)

    summary = (
        f"TP={tp} TN={tn} FP={fp} FN={fn} Ambiguous={amb} Errors={errs} | "
        f"Precision={overall.precision} Recall={overall.recall} F1={overall.f1} Accuracy={overall.accuracy}"
    )

    return EvaluationRun(
        run_id=run_id,
        timestamp=timestamp,
        dataset_version=dataset_version,
        dataset_id=dataset_id,
        dataset_hash=dataset_hash,
        offline=offline,
        no_llm=no_llm,
        cases_total=len(cases),
        cases_completed=len(results),
        overall_metrics=overall,
        per_category={k: v for k, v in per_cat.items()},
        case_results=results,
        patch_metrics=compute_patch_metrics([]),
        agent_metrics={},
        performance=perf,
        warnings=[],
        summary=summary,
    )
