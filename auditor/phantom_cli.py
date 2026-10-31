"""PHANTOM — AI-Powered Security Intelligence CLI.

This module is the new polished entry-point for the PHANTOM security auditor.
It wraps the existing core scan/remediate/evaluate logic with a professional
Rich-based terminal UI while preserving 100% of the functional behaviour.

Entry-points (setup.cfg / pyproject.toml):
    phantom  = auditor.phantom_cli:main
    auditor  = auditor.cli:main      (legacy, unchanged)
"""

from __future__ import annotations

import datetime
import io
import os
import sys
import time
import uuid
from pathlib import Path

# ── UTF-8 stdout on Windows ───────────────────────────────────────────────────
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import argparse
from typing import Optional

from auditor import __version__

# ── UI imports (graceful fallback if Rich missing) ────────────────────────────
try:
    from auditor.cli.ui.banner import print_banner, print_section, print_quiet_start
    from auditor.cli.ui.console import console, err_console, set_quiet, quiet_mode
    from auditor.cli.ui.findings_view import print_findings_table
    from auditor.cli.ui.panels import error_panel, warning_panel, success_panel, info_panel
    from auditor.cli.ui.progress import ScanProgress, simple_spinner
    from auditor.cli.ui.summary_view import (
        print_scan_summary,
        print_remediation_summary,
        print_evaluation_summary,
    )
    from auditor.cli.ui.tables import (
        print_dependency_table,
        print_agent_table,
        print_file_tree,
    )
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False

# ── Core imports ──────────────────────────────────────────────────────────────
from auditor.advisories import OSVClient, normalize_advisories_to_findings
from auditor.agents import AgentOrchestrator, AnalysisContext, AnalysisMode, get_provider
from auditor.core.config import ScanConfig
from auditor.core.models import Finding, ScanResult, ScanSummary
from auditor.core.safety import redact_secrets
from auditor.dependencies import DependencyGraphService, ManifestResolver
from auditor.graph import CodeGraphService
from auditor.ingestion.factory import get_ingester
from auditor.parser import ASTEngine
from auditor.sast import SASTEngine
from auditor.scanner.discovery import FileDiscoveryService


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phantom",
        description="PHANTOM — AI-Powered Security Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SCANNING
  phantom scan .                          Scan current directory
  phantom scan /path/to/repo --offline    Offline scan, no network
  phantom scan . --format json -o r.json  Save JSON report

ANALYSIS & FINDINGS
  phantom scan . --no-agents             SAST only, skip AI agents
  phantom scan . -v                      Verbose output

REMEDIATION
  phantom remediate ./src --validate      Generate & validate patches
  phantom remediate ./src --no-llm        Deterministic patches only

EVALUATION
  phantom evaluate                        Run full benchmark suite
  phantom evaluate --category sql         SQL injection cases only
  phantom evaluate --case-id CMD-001      Single benchmark case

FLAGS (all commands)
  --quiet / -q     Suppress banner and decorative output
  --no-color       Disable colour (also respects NO_COLOR env var)
  --verbose / -v   Detailed output
""",
    )
    parser.add_argument("--version", action="version", version=f"phantom {__version__}")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress startup banner")
    parser.add_argument("--no-color", action="store_true", help="Disable colour output")

    sub = parser.add_subparsers(dest="command")

    # ── scan ──────────────────────────────────────────────────────────────────
    sp = sub.add_parser("scan", help="Audit a local repository or remote Git URL")
    sp.add_argument("target", help="Directory path or Git URL")
    sp.add_argument("--format", default="terminal",
                    help="Comma-separated formats: terminal,json,markdown (default: terminal)")
    sp.add_argument("-o", "--output", default=None, help="Output file path for JSON/Markdown")
    sp.add_argument("--offline", action="store_true", help="No remote advisory or LLM calls")
    sp.add_argument("--no-sast", action="store_true", help="Skip SAST analysis")
    sp.add_argument("--no-deps", action="store_true", help="Skip dependency analysis")
    sp.add_argument("--no-agents", action="store_true", help="Skip AI agent analysis")
    sp.add_argument("--no-llm", action="store_true", help="Deterministic agents only")
    sp.add_argument("--llm-provider", default="auto")
    sp.add_argument("--llm-model", default=None)
    sp.add_argument("--agent-timeout", type=int, default=15)
    sp.add_argument("-v", "--verbose", action="store_true")
    sp.add_argument("-q", "--quiet", action="store_true")
    sp.add_argument("--no-color", action="store_true")

    # ── remediate ─────────────────────────────────────────────────────────────
    rp = sub.add_parser("remediate", help="Generate and validate remediation patches")
    rp.add_argument("target", help="Local directory path")
    rp.add_argument("--finding-id", default=None)
    rp.add_argument("--output-dir", default=None)
    rp.add_argument("--format", default="json,markdown")
    rp.add_argument("--offline", action="store_true")
    rp.add_argument("--no-llm", action="store_true")
    rp.add_argument("--validate", action="store_true")
    rp.add_argument("--run-tests", action="store_true")
    rp.add_argument("-v", "--verbose", action="store_true")
    rp.add_argument("-q", "--quiet", action="store_true")
    rp.add_argument("--no-color", action="store_true")

    # ── evaluate ──────────────────────────────────────────────────────────────
    ep = sub.add_parser("evaluate", help="Run benchmark evaluation")
    ep.add_argument("--dataset", default="benchmarks/manifest.json")
    ep.add_argument("--output-dir", default=None)
    ep.add_argument("--format", default="json,markdown")
    ep.add_argument("--offline", action="store_true")
    ep.add_argument("--no-llm", action="store_true")
    ep.add_argument("--category", default=None)
    ep.add_argument("--case-id", default=None)
    ep.add_argument("-v", "--verbose", action="store_true")
    ep.add_argument("-q", "--quiet", action="store_true")
    ep.add_argument("--no-color", action="store_true")

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# _cprint — safe print that works with or without Rich
# ─────────────────────────────────────────────────────────────────────────────

def _cprint(msg: str, **kw) -> None:
    if _RICH_AVAILABLE:
        console.print(msg, **kw)
    else:
        import re
        print(re.sub(r"\[.*?\]", "", msg))


def _eprint(msg: str) -> None:
    if _RICH_AVAILABLE:
        err_console.print(msg)
    else:
        import re
        print(re.sub(r"\[.*?\]", "", msg), file=sys.stderr)


# ─────────────────────────────────────────────────────────────────────────────
# phantom scan
# ─────────────────────────────────────────────────────────────────────────────

def _run_scan(args: argparse.Namespace, quiet: bool) -> int:  # noqa: C901
    formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]

    config = ScanConfig(
        target=args.target,
        output_formats=formats,
        output_path=getattr(args, "output", None),
        offline_mode=args.offline,
        include_sast=not args.no_sast,
        include_deps=not args.no_deps,
        include_agents=not args.no_agents,
        enable_llm=not args.no_llm,
        llm_provider=args.llm_provider,
        llm_model=args.llm_model,
        agent_timeout_seconds=args.agent_timeout,
        verbose=args.verbose,
    )

    scan_id   = str(uuid.uuid4())[:8]
    start_ts  = time.time()
    findings  : list[Finding] = []
    dep_records   = []
    sast_findings_count = 0
    graph_metrics: dict = {}
    agent_traces : list  = []
    agents_executed = agents_skipped = agents_failed = 0
    orchestrator_mode = "SKIPPED"
    sast_engine = None

    # ── info panel ────────────────────────────────────────────────────────────
    if not quiet and _RICH_AVAILABLE:
        info_panel(
            f"PHANTOM / SECURITY SCAN  [muted][{scan_id}][/]",
            [
                ("Repository",  args.target),
                ("Mode",        "[warn]OFFLINE[/]" if args.offline else "[ok]ONLINE[/]"),
                ("SAST",        "[ok]Enabled[/]" if config.include_sast else "[muted]Disabled[/]"),
                ("Dependencies","[ok]Enabled[/]" if config.include_deps else "[muted]Disabled[/]"),
                ("AI Agents",   "[ok]Enabled[/]" if config.include_agents else "[muted]Disabled[/]"),
                ("LLM",         "[muted]Disabled[/]" if not config.enable_llm else "[ok]Enabled[/]"),
            ],
        )
    else:
        _cprint(f"[phantom]PHANTOM[/] scan [muted][{scan_id}][/]  target=[value]{args.target}[/]")

    # ── progress context ───────────────────────────────────────────────────────
    STEP_INGEST  = "Repository ingestion"
    STEP_DISC    = "File discovery"
    STEP_DEPS    = "Dependency analysis"
    STEP_AST     = "AST parsing"
    STEP_SAST    = "SAST analysis"
    STEP_AGENTS  = "Agent analysis"
    STEP_REPORT  = "Generating report"

    all_steps = [STEP_INGEST, STEP_DISC, STEP_DEPS, STEP_AST, STEP_SAST, STEP_AGENTS, STEP_REPORT]

    use_progress = not quiet and _RICH_AVAILABLE

    # We drive the existing logic manually, updating progress as we go.
    # Wrap the whole thing so we can catch errors and still show the UI.
    try:
        if use_progress:
            sp = ScanProgress(all_steps)
            sp.__enter__()
        else:
            sp = None

        def _step_start(name, note=""):
            if sp: sp.start_step(name, note)
        def _step_done(name, note=""):
            if sp: sp.done_step(name, note)
        def _step_skip(name, note="skipped"):
            if sp: sp.skip_step(name, note)
        def _step_fail(name, note="failed"):
            if sp: sp.fail_step(name, note)

        # 1. Ingest
        _step_start(STEP_INGEST)
        ingester = get_ingester(config.target)
        repo = ingester.ingest(config.target)
        _step_done(STEP_INGEST, f"[path]{repo.working_dir}[/]")

        # 2. Discover
        _step_start(STEP_DISC)
        discovery_svc = FileDiscoveryService()
        disc = discovery_svc.discover(repo.working_dir)
        lang_str = "  ".join(f"{k}:{v}" for k, v in disc.language_counts.items())
        _step_done(STEP_DISC, f"{disc.total_discovered} files  {lang_str}")

        # 3. Dependencies
        if config.include_deps and disc.manifest_files:
            _step_start(STEP_DEPS)
            try:
                resolver = ManifestResolver()
                dep_records = resolver.resolve_all(disc.manifest_files)
                if dep_records and not config.offline_mode:
                    osv = OSVClient()
                    queries = [(r.ecosystem, r.normalized_name, r.version or "") for r in dep_records if r.version]
                    osv_results = osv.query_batch(queries)
                    for res in osv_results:
                        new_f = normalize_advisories_to_findings(res.advisories, res.package_name, res.ecosystem, res.version)
                        findings.extend(new_f)
                graph_svc = DependencyGraphService()
                graph_svc.build_graph(dep_records)
                graph_metrics["dependency"] = graph_svc.to_dict().get("metrics", {})
                _step_done(STEP_DEPS, f"{len(dep_records)} packages")
            except Exception as dep_err:
                _step_fail(STEP_DEPS, str(dep_err)[:60])
                if config.verbose:
                    import traceback; traceback.print_exc()
        elif not config.include_deps:
            _step_skip(STEP_DEPS, "--no-deps")
        else:
            _step_skip(STEP_DEPS, "no manifests")

        # 4 + 5. AST + SAST
        parsed_files = []
        if config.include_sast and disc.source_files:
            _step_start(STEP_AST)
            try:
                ast_engine = ASTEngine()
                parsed_files = ast_engine.parse_all(disc.source_files)
                code_graph_svc = CodeGraphService()
                code_graph_svc.build_graph(parsed_files)
                cg = code_graph_svc.to_dict()["metrics"]
                graph_metrics["code"] = cg
                _step_done(STEP_AST, f"{cg['files_count']} files  {cg['functions_count']} fns")
            except Exception as e:
                _step_fail(STEP_AST, str(e)[:60])

            _step_start(STEP_SAST)
            try:
                sast_engine = SASTEngine()
                sast_findings = sast_engine.scan_all(parsed_files)
                sast_findings_count = len(sast_findings)
                findings.extend(sast_findings)
                _step_done(STEP_SAST, f"{sast_findings_count} findings  {len(sast_engine.rules)} rules")
            except Exception as e:
                _step_fail(STEP_SAST, str(e)[:60])
        elif not config.include_sast:
            _step_skip(STEP_AST, "--no-sast")
            _step_skip(STEP_SAST, "--no-sast")
        else:
            _step_skip(STEP_AST, "no source files")
            _step_skip(STEP_SAST, "no source files")

        # 6. Agents
        if config.include_agents:
            _step_start(STEP_AGENTS)
            try:
                provider = get_provider(config)
                mode = AnalysisMode.LLM if provider.is_online else AnalysisMode.DETERMINISTIC
                orchestrator_mode = "LLM_ASSISTED" if provider.is_online else "OFFLINE_DETERMINISTIC"

                source_excerpts: dict[str, str] = {}
                for sf in (disc.source_files or [])[:20]:
                    try:
                        raw = Path(sf.path).read_text(encoding="utf-8", errors="replace")
                        source_excerpts[sf.relative_path] = redact_secrets(raw[:500])
                    except Exception:
                        pass

                dep_summary = [
                    {"name": r.normalized_name, "version": r.version or "UNRESOLVED",
                     "ecosystem": r.ecosystem, "is_direct": r.is_direct}
                    for r in dep_records
                ]
                ctx = AnalysisContext(
                    scan_id=scan_id, findings=findings, graph_metrics=graph_metrics,
                    source_excerpts=source_excerpts, dep_records_summary=dep_summary, mode=mode,
                )
                orch = AgentOrchestrator(config, provider)
                orch_result = orch.run(ctx, findings)
                findings = orch_result.updated_findings
                agents_executed = orch_result.agents_executed_count
                agents_skipped  = orch_result.agents_skipped_count
                agents_failed   = orch_result.agents_failed_count
                orchestrator_mode = orch_result.orchestrator_mode
                for ar in orch_result.agent_results:
                    agent_traces.append({
                        "agent_id": ar.agent_id, "role": ar.role,
                        "status": ar.status.value, "summary": ar.summary,
                        "mode": ar.analysis_mode.value,
                        "duration_seconds": ar.duration_seconds,
                        "reviewed_count": len(ar.reviewed_finding_ids),
                        "warnings": ar.warnings,
                    })
                _step_done(STEP_AGENTS, f"{agents_executed} agents  [{orchestrator_mode}]")
            except Exception as e:
                _step_fail(STEP_AGENTS, str(e)[:60])
                if config.verbose:
                    import traceback; traceback.print_exc()
        else:
            _step_skip(STEP_AGENTS, "--no-agents")

        # 7. Report step
        _step_start(STEP_REPORT)

        elapsed = time.time() - start_ts
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        direct_count     = sum(1 for r in dep_records if r.is_direct)
        transitive_count = len(dep_records) - direct_count

        summary = ScanSummary(
            total_files_discovered=disc.total_discovered,
            scanned_files_count=len(disc.files),
            skipped_files_count=disc.skipped_count,
            languages=disc.language_counts,
            findings_count_by_severity=sev_counts,
            duration_seconds=elapsed,
            manifests_discovered_count=len(disc.manifest_files),
            manifests_parsed_count=len(disc.manifest_files),
            dependencies_total_count=len(dep_records),
            direct_dependencies_count=direct_count,
            transitive_dependencies_count=transitive_count,
            packages_checked_advisories_count=len(dep_records),
            advisory_matches_count=len(findings) - sast_findings_count,
            advisory_lookup_failures_count=0,
            cache_hits_count=0,
            source_files_discovered_count=len(disc.source_files),
            source_files_parsed_count=len(parsed_files),
            source_files_failed_count=len(disc.source_files) - len(parsed_files),
            sast_findings_count=sast_findings_count,
            sast_rules_executed_count=len(sast_engine.rules) if sast_engine else 0,
            agents_executed_count=agents_executed,
            agents_skipped_count=agents_skipped,
            agents_failed_count=agents_failed,
        )

        result = ScanResult(
            scan_id=scan_id,
            target_path_or_url=config.target,
            summary=summary,
            findings=findings,
            graph_metrics=graph_metrics,
            metadata={
                "ingester": ingester.__class__.__name__,
                "is_temporary": repo.is_temporary,
                "offline_mode": config.offline_mode,
            },
            agent_traces=agent_traces,
            orchestrator_mode=orchestrator_mode,
        )

        # Save outputs
        report_paths: list[str] = []
        if config.output_path:
            out_path = Path(config.output_path)
            out_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
            report_paths.append(str(out_path.resolve()))
            if "markdown" in formats:
                from auditor.cli import _write_scan_markdown_compat
                md_path = out_path.with_suffix(".md")
                _write_scan_markdown_compat(result, md_path)
                report_paths.append(str(md_path.resolve()))
        _step_done(STEP_REPORT)

        # Stop progress display before printing results
        if sp:
            sp.__exit__(None, None, None)
            sp = None

    except Exception as exc:
        if sp:
            try: sp.__exit__(None, None, None)
            except Exception: pass
        if _RICH_AVAILABLE:
            error_panel(str(exc), hint="Run with --verbose for a full traceback.")
        else:
            print(f"[-] Scan failed: {exc}", file=sys.stderr)
        if getattr(args, "verbose", False):
            import traceback; traceback.print_exc()
        return 1

    # ── Display results ────────────────────────────────────────────────────────
    if not quiet and _RICH_AVAILABLE:
        console.print()
        print_findings_table(findings)
        if args.verbose and agent_traces:
            print_agent_table(agent_traces)
        print_scan_summary(
            result,
            report_paths=report_paths or None,
            next_cmd=("phantom remediate . --validate" if findings else "phantom evaluate"),
        )
    else:
        # Plain fallback summary
        _cprint(f"[ok]Scan complete[/]  "
                f"files=[value]{summary.scanned_files_count}[/]  "
                f"findings=[value]{sum(sev_counts.values())}[/]  "
                f"duration=[muted]{elapsed:.2f}s[/]")
        if findings:
            for idx, f in enumerate(sorted(findings, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(x.severity.value,5))[:10], 1):
                loc = f.locations[0] if f.locations else None
                loc_str = f" {loc.file_path}:{loc.line}" if loc else ""
                _cprint(f"  [{f.severity.value}] {f.title}{loc_str}")
        for p in report_paths:
            _cprint(f"[ok]Report saved:[/] [path]{p}[/]")

    return 0


# ─────────────────────────────────────────────────────────────────────────────
# phantom remediate  (delegates to auditor.cli.run_remediate)
# ─────────────────────────────────────────────────────────────────────────────

def _run_remediate(args: argparse.Namespace, quiet: bool) -> int:
    import uuid as _uuid
    from auditor.core.config import ScanConfig
    from auditor.remediation import PatchGenerator, PatchValidator, RemediationReport
    from auditor.remediation.reporter import save_json_report, save_markdown_report, save_patch_files

    target = Path(args.target).resolve()
    if not target.exists() or not target.is_dir():
        if _RICH_AVAILABLE:
            error_panel(f"Target directory not found: {target}")
        else:
            print(f"[-] Target directory not found: {target}", file=sys.stderr)
        return 1

    output_dir = Path(args.output_dir) if args.output_dir else target / "remediation-output"
    offline    = getattr(args, "offline", False)
    no_llm     = getattr(args, "no_llm", False)
    validate   = getattr(args, "validate", False)
    run_tests  = getattr(args, "run_tests", False)
    fid_filter = getattr(args, "finding_id", None)
    formats    = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    verbose    = getattr(args, "verbose", False)
    run_id     = str(_uuid.uuid4())[:8]

    if not quiet and _RICH_AVAILABLE:
        info_panel(
            f"PHANTOM / REMEDIATION  [muted][{run_id}][/]",
            [
                ("Target",    str(target)),
                ("Mode",      "[warn]OFFLINE[/]" if offline else "[ok]ONLINE[/]"),
                ("LLM",       "[muted]Disabled[/]" if no_llm else "[ok]Enabled[/]"),
                ("Validate",  "[ok]Yes[/]" if validate else "[muted]No[/]"),
            ],
        )
    else:
        _cprint(f"[phantom]PHANTOM[/] remediate [muted][{run_id}][/]  target=[value]{target}[/]")

    # ── Step 1: scan ──────────────────────────────────────────────────────────
    if not quiet: _cprint("[muted][1/4] Scanning for vulnerabilities...[/]")
    scan_config = ScanConfig(
        target=str(target), offline_mode=offline, enable_llm=not no_llm,
        include_sast=True, include_deps=True, include_agents=False,
    )
    try:
        ingester = get_ingester(str(target))
        repo = ingester.ingest(str(target))
        disc_svc = FileDiscoveryService()
        disc = disc_svc.discover(repo.working_dir)
        parsed_files = []
        all_findings: list[Finding] = []
        if disc.source_files:
            ast_engine = ASTEngine()
            parsed_files = ast_engine.parse_all(disc.source_files)
            sast_engine = SASTEngine()
            all_findings = sast_engine.scan_all(parsed_files)
        if fid_filter:
            all_findings = [f for f in all_findings if f.id == fid_filter]
    except Exception as e:
        _eprint(f"[err]Scan failed: {e}[/]")
        if verbose:
            import traceback; traceback.print_exc()
        return 1

    _cprint(f"  [ok]+[/] Found [value]{len(all_findings)}[/] finding(s)")

    # ── Step 2: generate ──────────────────────────────────────────────────────
    if not quiet: _cprint("[muted][2/4] Generating patch proposals...[/]")
    try:
        generator = PatchGenerator(repo_root=str(target))
        proposals = generator.generate_all(all_findings)
    except Exception as e:
        _eprint(f"[err]Patch generation failed: {e}[/]")
        return 1

    eligible    = [p for p in proposals if p.status.value != "unsupported"]
    unsupported = [p for p in proposals if p.status.value == "unsupported"]
    _cprint(f"  [ok]+[/] Generated [value]{len(eligible)}[/] proposal(s), [muted]{len(unsupported)}[/] unsupported")

    # ── Step 3: validate ──────────────────────────────────────────────────────
    validation_results = []
    if validate and eligible:
        if not quiet: _cprint("[muted][3/4] Validating proposals...[/]")
        try:
            validator = PatchValidator(repo_root=str(target), run_tests=run_tests)
            for prop in eligible:
                vr = validator.validate(prop)
                validation_results.append(vr)
                status_style = "ok" if vr.overall_status.value == "validated" else "warn"
                _cprint(f"  [{status_style}]  {prop.patch_id}: {vr.overall_status.value}[/]")
        except Exception as e:
            _eprint(f"[err]Validation failed: {e}[/]")
    else:
        if not quiet: _cprint("[muted][3/4] Validation skipped (use --validate to enable)[/]")

    # ── Step 4: save ──────────────────────────────────────────────────────────
    if not quiet: _cprint("[muted][4/4] Saving reports...[/]")
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        report = RemediationReport(
            scan_id=run_id,
            target=str(target),
            proposals=proposals,
            validation_results=validation_results,
        )
        report_paths: list[str] = []
        if "json" in formats:
            jp = save_json_report(report, output_dir / "reports")
            report_paths.append(str(jp))
        if "markdown" in formats:
            mp = save_markdown_report(report, output_dir / "reports")
            report_paths.append(str(mp))
    except Exception as e:
        _eprint(f"[warn]Report save warning: {e}[/]")
        report_paths = []

    if not quiet and _RICH_AVAILABLE:
        print_remediation_summary(report, report_paths=report_paths)
    else:
        _cprint(f"[ok]Remediation complete[/]  proposals=[value]{len(proposals)}[/]")
        for p in report_paths:
            _cprint(f"[ok]Report:[/] [path]{p}[/]")

    return 0


# ─────────────────────────────────────────────────────────────────────────────
# phantom evaluate  (delegates to auditor.cli.run_evaluate logic)
# ─────────────────────────────────────────────────────────────────────────────

def _run_evaluate(args: argparse.Namespace, quiet: bool) -> int:
    from auditor.cli_legacy import run_evaluate as _legacy_eval
    return _legacy_eval(args)


# ─────────────────────────────────────────────────────────────────────────────
# main entry-point
# ─────────────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Apply --no-color before anything touches Rich
    no_color = getattr(args, "no_color", False) or os.environ.get("NO_COLOR") is not None
    if no_color:
        os.environ["NO_COLOR"] = "1"
        if _RICH_AVAILABLE:
            # Swap in a plain no-color console for all UI modules
            from rich.console import Console as _RichConsole
            import auditor.cli.ui.console as _con_mod
            from auditor.cli.ui.theme import THEME as _THEME
            _plain = _RichConsole(no_color=True, markup=True, emoji=False,
                                  theme=_THEME, highlight=False)
            _plain_err = _RichConsole(no_color=True, markup=True, emoji=False,
                                      stderr=True, theme=_THEME, highlight=False)
            _con_mod.console = _plain
            _con_mod.err_console = _plain_err
            import auditor.cli.ui.banner as _banner_mod
            import auditor.cli.ui.panels as _panels_mod
            import auditor.cli.ui.findings_view as _fv_mod
            import auditor.cli.ui.summary_view as _sv_mod
            import auditor.cli.ui.tables as _tables_mod
            for _mod in (_banner_mod, _panels_mod, _fv_mod, _sv_mod, _tables_mod):
                if hasattr(_mod, "console"):
                    _mod.console = _plain

    quiet = getattr(args, "quiet", False)
    if _RICH_AVAILABLE:
        set_quiet(quiet)

    if not args.command:
        # No subcommand → show banner + help
        if not quiet and _RICH_AVAILABLE:
            print_banner(__version__, quiet=quiet)
        elif not quiet:
            print(f"PHANTOM v{__version__}  |  AI-Powered Security Intelligence")
        parser.print_help()
        return 0

    # Show banner for interactive commands (not in quiet/CI)
    if not quiet and _RICH_AVAILABLE:
        offline = getattr(args, "offline", False)
        print_banner(__version__, offline=offline, quiet=quiet)
    elif not quiet:
        print(f"PHANTOM v{__version__}  |  AI-Powered Security Intelligence")

    if args.command == "scan":
        return _run_scan(args, quiet)
    if args.command == "remediate":
        return _run_remediate(args, quiet)
    if args.command == "evaluate":
        return _run_evaluate(args, quiet)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
