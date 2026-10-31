"""Command Line Interface for the Codebase Vulnerability and Dependency Graph Auditor."""

from __future__ import annotations

import argparse
import io
import sys
import time
import uuid
from pathlib import Path

# Ensure stdout/stderr use UTF-8 on Windows (avoids cp1252 UnicodeEncodeError for any
# Unicode characters in print output, e.g. in agent summaries or diff snippets).
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from auditor import __version__
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditor",
        description="Automated Multi-Agent Codebase Vulnerability and Dependency Graph Auditor",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Audit a local repository or remote Git URL")
    scan_parser.add_argument(
        "target",
        type=str,
        help="Local directory path or Git clone URL (e.g., https://github.com/owner/repo.git)",
    )
    scan_parser.add_argument(
        "--format",
        type=str,
        default="terminal",
        help="Comma-separated report formats: terminal, json, markdown, sarif (default: terminal)",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="File path to write report output",
    )
    scan_parser.add_argument(
        "--offline",
        action="store_true",
        help="Run in offline mode (do not query remote advisory databases or LLM APIs)",
    )
    scan_parser.add_argument(
        "--no-sast",
        action="store_true",
        help="Disable static application security testing",
    )
    scan_parser.add_argument(
        "--no-deps",
        action="store_true",
        help="Disable dependency manifest vulnerability checks",
    )
    scan_parser.add_argument(
        "--no-agents",
        action="store_true",
        help="Disable AI agent contextual analysis",
    )
    scan_parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM provider calls; use deterministic agent fallback only",
    )
    scan_parser.add_argument(
        "--llm-provider",
        type=str,
        default="auto",
        help="LLM provider: auto, openai, offline (default: auto)",
    )
    scan_parser.add_argument(
        "--llm-model",
        type=str,
        default=None,
        help="Specific LLM model identifier (e.g. gpt-4o-mini)",
    )
    scan_parser.add_argument(
        "--agent-timeout",
        type=int,
        default=15,
        help="Per-agent execution timeout in seconds (default: 15)",
    )
    scan_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    # ---------------------------------------------------------------
    # remediate subcommand
    # ---------------------------------------------------------------
    rem_parser = subparsers.add_parser(
        "remediate",
        help="Generate and validate remediation patches for detected vulnerabilities",
    )
    rem_parser.add_argument(
        "target",
        type=str,
        help="Local directory path to audit and remediate",
    )
    rem_parser.add_argument(
        "--finding-id",
        type=str,
        default=None,
        help="Remediate only this specific finding ID",
    )
    rem_parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to store patches and remediation reports (default: <target>/remediation-output)",
    )
    rem_parser.add_argument(
        "--format",
        type=str,
        default="json,markdown",
        help="Comma-separated report formats: json, markdown (default: json,markdown)",
    )
    rem_parser.add_argument(
        "--offline",
        action="store_true",
        help="Offline mode — no advisory or LLM network calls",
    )
    rem_parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM-assisted patch generation",
    )
    rem_parser.add_argument(
        "--validate",
        action="store_true",
        help="Run validation checks on generated proposals",
    )
    rem_parser.add_argument(
        "--run-tests",
        action="store_true",
        help="Run existing tests in isolated workspace during validation (opt-in)",
    )
    rem_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    # ---------------------------------------------------------------
    # evaluate subcommand
    # ---------------------------------------------------------------
    eval_parser = subparsers.add_parser(
        "evaluate",
        help="Run benchmark evaluation against ground-truth dataset",
    )
    eval_parser.add_argument(
        "--dataset",
        type=str,
        default="benchmarks/manifest.json",
        help="Path to benchmark manifest JSON (default: benchmarks/manifest.json)",
    )
    eval_parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory for evaluation reports (default: reports/evaluation)",
    )
    eval_parser.add_argument(
        "--format",
        type=str,
        default="json,markdown",
        help="Comma-separated report formats: json, markdown (default: json,markdown)",
    )
    eval_parser.add_argument(
        "--offline",
        action="store_true",
        help="Run in offline mode (no network calls)",
    )
    eval_parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM provider calls during evaluation",
    )
    eval_parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="Filter evaluation to a single category (e.g., sql, cmd, deps)",
    )
    eval_parser.add_argument(
        "--case-id",
        type=str,
        default=None,
        help="Filter evaluation to a single case ID (e.g., SQL-001)",
    )
    eval_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    return parser


def _write_scan_markdown(result: "ScanResult", md_path: "Path") -> None:
    """Write a simple Markdown report for a scan result."""
    from auditor.core.models import ScanResult  # noqa: F401
    lines = [
        f"# SYNTAXIS Scan Report",
        f"",
        f"**Scan ID:** `{result.scan_id}`  ",
        f"**Target:** `{result.target_path_or_url}`  ",
        f"**Timestamp:** {result.timestamp}  ",
        f"",
        f"## Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Files Analyzed | {result.summary.scanned_files_count} |",
        f"| Duration | {result.summary.duration_seconds:.2f}s |",
        f"| Findings | {result.summary.findings_count_by_severity} |",
        f"",
        f"### Severity Breakdown",
        f"",
    ]
    for sev, cnt in result.summary.findings_count_by_severity.items():
        lines.append(f"- **{sev}**: {cnt}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not result.findings:
        lines.append("_No security findings detected._")
    else:
        for f in result.findings:
            if f.locations:
                loc = f.locations[0]
                heading = f"### [{f.severity.value}] {f.title} - `{loc.file_path}:{loc.line}`"
            else:
                heading = f"### [{f.severity.value}] {f.title}"
            lines.append(heading)
            lines.append("")
            lines.append(f"> **Type:** {f.finding_type.value}  ")
            if f.cwe_id:
                lines.append(f"> **CWE:** {f.cwe_id}  ")
            lines.append(f"> **Remediation:** {f.remediation_advice}")
            lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")


def run_scan(config: ScanConfig) -> int:
    start_time = time.time()
    scan_id = str(uuid.uuid4())[:8]

    print("=" * 65)
    print(f" Codebase Vulnerability Auditor v{__version__} [Scan ID: {scan_id}]")
    print("=" * 65)
    print(f"[*] Target: {config.target}")
    print(f"[*] Mode: {'OFFLINE' if config.offline_mode else 'ONLINE'}")
    print(f"[*] SAST: {'Enabled' if config.include_sast else 'Disabled'} | Deps: {'Enabled' if config.include_deps else 'Disabled'} | Agents: {'Enabled' if config.include_agents else 'Disabled'}")
    print("=" * 65)

    ingester = get_ingester(config.target)
    print(f"[1/4] Ingesting repository using {ingester.__class__.__name__}...")

    try:
        with ingester.ingest(config.target) as repo:
            print(f"[+] Target staged at: {repo.working_dir}")

            print("[2/4] Discovering source files, languages, and manifests...")
            discovery_service = FileDiscoveryService()
            disc = discovery_service.discover(repo.working_dir)

            print(f"[+] Discovered {len(disc.files)} analyzable files ({disc.skipped_count} skipped).")
            if disc.language_counts:
                print(f"[+] Detected languages: {', '.join(f'{k}: {v}' for k, v in disc.language_counts.items())}")
            else:
                print("[!] No recognized programming language source files found.")

            if disc.manifest_files:
                print(f"[+] Detected dependency manifests ({len(disc.manifest_files)}):")
                for mf in disc.manifest_files:
                    print(f"    - {mf.relative_path} ({mf.manifest_type})")
            else:
                print("[*] No package dependency manifests detected.")

            print("[3/4] Running security analysis (dependencies & SAST)...")
            dep_records = []
            findings: list[Finding] = []
            graph_metrics = {}
            advisories_checked_count = 0
            advisory_matches_count = 0
            lookup_failures_count = 0
            cache_hits_count = 0

            # 3A. Dependency Intelligence
            if config.include_deps and disc.manifest_files:
                resolver = ManifestResolver()
                dep_records = resolver.resolve_all(disc.manifest_files)
                print(f"[+] Extracted {len(dep_records)} dependency declarations across {len(disc.manifest_files)} manifests.")

                # Construct NetworkX dependency graph
                graph_service = DependencyGraphService()
                graph_service.build_graph(dep_records)
                dep_graph_dict = graph_service.to_dict()
                graph_metrics.update(dep_graph_dict["metrics"])
                graph_metrics["dependencies"] = dep_graph_dict["metrics"]

                print(f"[+] Dependency Graph: {dep_graph_dict['metrics']['total_package_nodes']} nodes, {dep_graph_dict['metrics']['total_dependency_edges']} edges ({dep_graph_dict['metrics']['direct_dependencies_count']} direct).")
                if not dep_graph_dict["metrics"]["is_relationship_data_complete"]:
                    print("[!] Note: Manifest structure provides partial relationship tree; transitive dependencies represented where available.")

                resolved_queries = [
                    (r.ecosystem, r.normalized_name, r.version)
                    for r in dep_records
                    if r.version
                ]
                unique_queries = list({(q[0], q[1], q[2]) for q in resolved_queries})
                advisories_checked_count = len(unique_queries)

                if unique_queries:
                    print(f"[*] Correlating {advisories_checked_count} resolved packages with OSV (offline={config.offline_mode})...")
                    osv_client = OSVClient(offline=config.offline_mode)
                    query_results = osv_client.query_batch(unique_queries)

                    for qr in query_results:
                        if qr.is_cached:
                            cache_hits_count += 1
                        if qr.status.value == "MATCHED":
                            advisory_matches_count += 1
                        elif qr.status.value in ("ERROR", "UNAVAILABLE_OFFLINE"):
                            lookup_failures_count += 1

                    dep_findings = normalize_advisories_to_findings(query_results, dep_records)
                    findings.extend(dep_findings)
                    print(f"[+] Identified {len(dep_findings)} dependency vulnerability findings ({cache_hits_count} cache hits).")
                    if lookup_failures_count > 0:
                        print(f"[!] Warning: {lookup_failures_count} package queries could not be completed (offline mode or network failure).")
                else:
                    print("[*] No resolved package versions available for advisory lookup.")
            elif not config.include_deps:
                print("[*] Dependency analysis skipped (--no-deps specified).")
            else:
                print("[*] No dependency manifests found to analyze.")

            # 3B. Deterministic SAST & Code Relationship Graph
            source_parsed_count = 0
            source_failed_count = 0
            sast_findings_count = 0
            sast_engine = None  # initialized here so it's always defined

            if config.include_sast and disc.source_files:
                print(f"[*] Parsing {len(disc.source_files)} source files for AST analysis...")
                ast_engine = ASTEngine()
                parsed_files = ast_engine.parse_all(disc.source_files)

                source_parsed_count = sum(1 for pf in parsed_files if pf.is_success)
                source_failed_count = sum(1 for pf in parsed_files if not pf.is_success)

                if source_failed_count > 0:
                    print(f"[!] Warning: {source_failed_count} source files encountered parse errors or unsupported syntax.")

                # Build NetworkX code graph
                code_graph_service = CodeGraphService()
                code_graph_service.build_graph(parsed_files)
                code_graph_dict = code_graph_service.to_dict()
                graph_metrics["code"] = code_graph_dict["metrics"]
                cg_metrics = code_graph_dict["metrics"]
                print(f"[+] Code Graph: {cg_metrics['files_count']} files, {cg_metrics['classes_count']} classes, {cg_metrics['functions_count']} functions, {cg_metrics['calls_count']} calls ({cg_metrics['resolved_calls']} resolved).")

                # Run SAST Engine & Data-flow checks
                sast_engine = SASTEngine()
                sast_findings = sast_engine.scan_all(parsed_files)
                sast_findings_count = len(sast_findings)
                findings.extend(sast_findings)
                print(f"[+] SAST scan: {sast_findings_count} security findings detected across {len(sast_engine.rules)} deterministic rules.")
            elif not config.include_sast:
                print("[*] SAST analysis skipped (--no-sast specified).")
            else:
                print("[*] No source code files found for SAST analysis.")

            # 3C. Phase D — Multi-Agent Orchestration
            agent_traces = []
            agents_executed = 0
            agents_skipped = 0
            agents_failed = 0
            orchestrator_mode = "SKIPPED"

            if config.include_agents:
                print(f"[*] Running multi-agent analysis ({'OFFLINE_DETERMINISTIC' if config.offline_mode or not config.enable_llm else 'LLM_ASSISTED'})...")
                provider = get_provider(config)
                orchestrator_mode = "LLM_ASSISTED" if provider.is_online else "OFFLINE_DETERMINISTIC"

                # Build source excerpts (redacted, max 500 chars per file)
                source_excerpts: dict[str, str] = {}
                if disc.source_files:
                    for sf in disc.source_files[:20]:  # cap to 20 files
                        try:
                            raw = Path(sf.path).read_text(encoding="utf-8", errors="replace")
                            source_excerpts[sf.relative_path] = redact_secrets(raw[:500])
                        except Exception:
                            pass

                # Build dependency summary (no secrets, no raw file contents)
                dep_summary = [
                    {
                        "name": r.normalized_name,
                        "version": r.version or "UNRESOLVED",
                        "ecosystem": r.ecosystem,
                        "is_direct": r.is_direct,
                    }
                    for r in dep_records
                ]

                analysis_context = AnalysisContext(
                    scan_id=scan_id,
                    findings=findings,
                    graph_metrics=graph_metrics,
                    source_excerpts=source_excerpts,
                    dep_records_summary=dep_summary,
                    mode=AnalysisMode.LLM if provider.is_online else AnalysisMode.DETERMINISTIC,
                )

                try:
                    orchestrator = AgentOrchestrator(config, provider)
                    orch_result = orchestrator.run(analysis_context, findings)

                    # Replace findings with agent-annotated versions
                    findings = orch_result.updated_findings
                    agents_executed = orch_result.agents_executed_count
                    agents_skipped = orch_result.agents_skipped_count
                    agents_failed = orch_result.agents_failed_count
                    orchestrator_mode = orch_result.orchestrator_mode

                    # Build trace entries for each agent result
                    for ar in orch_result.agent_results:
                        agent_traces.append({
                            "agent_id": ar.agent_id,
                            "role": ar.role,
                            "status": ar.status.value,
                            "summary": ar.summary,
                            "mode": ar.analysis_mode.value,
                            "duration_seconds": ar.duration_seconds,
                            "reviewed_count": len(ar.reviewed_finding_ids),
                            "warnings": ar.warnings,
                        })

                    if orch_result.warnings:
                        for w in orch_result.warnings:
                            print(f"[!] Agent warning: {w}")

                    print(
                        f"[+] Agents: {agents_executed} executed, "
                        f"{agents_skipped} skipped, {agents_failed} failed "
                        f"[Mode: {orchestrator_mode}]"
                    )
                except Exception as exc:
                    print(f"[!] Agent orchestration error (findings preserved): {exc}")
                    if config.verbose:
                        import traceback
                        traceback.print_exc()
                    orchestrator_mode = "FAILED"
            else:
                print("[*] Agent analysis skipped (--no-agents specified).")

            # Calculate severity distribution
            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in findings:
                sev_key = f.severity.value
                sev_counts[sev_key] = sev_counts.get(sev_key, 0) + 1

            elapsed = time.time() - start_time

            direct_count = sum(1 for r in dep_records if r.is_direct)
            transitive_count = len(dep_records) - direct_count

            summary = ScanSummary(
                total_files_discovered=disc.total_discovered,
                scanned_files_count=len(disc.files),
                skipped_files_count=disc.skipped_count,
                languages=disc.language_counts,
                findings_count_by_severity=sev_counts,
                duration_seconds=round(elapsed, 3),
                manifests_discovered_count=len(disc.manifest_files),
                manifests_parsed_count=len(disc.manifest_files) if config.include_deps else 0,
                dependencies_total_count=len(dep_records),
                direct_dependencies_count=direct_count,
                transitive_dependencies_count=transitive_count,
                packages_checked_advisories_count=advisories_checked_count,
                advisory_matches_count=advisory_matches_count,
                advisory_lookup_failures_count=lookup_failures_count,
                cache_hits_count=cache_hits_count,
                source_files_discovered_count=len(disc.source_files),
                source_files_parsed_count=source_parsed_count,
                source_files_failed_count=source_failed_count,
                sast_findings_count=sast_findings_count,
                sast_rules_executed_count=len(sast_engine.rules) if (config.include_sast and sast_engine is not None) else 0,
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

            print("[4/4] Scan complete.")
            print("-" * 65)
            print(f"Summary: {summary.scanned_files_count} files analyzed in {summary.duration_seconds:.2f}s | {len(findings)} findings reported ({len(findings) - sast_findings_count} deps, {sast_findings_count} SAST)")
            print(f"Severity Breakdown: Critical: {sev_counts['CRITICAL']} | High: {sev_counts['HIGH']} | Medium: {sev_counts['MEDIUM']} | Low: {sev_counts['LOW']}")
            if config.include_agents:
                print(f"Agents: {agents_executed} executed, {agents_skipped} skipped, {agents_failed} failed | Mode: {orchestrator_mode}")
            if findings:
                print("\nTop Findings:")
                for finding in findings[:5]:
                    cve_str = f" ({finding.cve_id})" if finding.cve_id else ""
                    print(f"  [{finding.severity.value}] [{finding.finding_type.value}] {finding.title}{cve_str}")
                    if finding.package_name:
                        print(f"      Package: {finding.package_name}@{finding.current_version}")
                    if finding.locations:
                        loc = finding.locations[0]
                        print(f"      Location: {loc.file_path}:{loc.line}")
                    print(f"      Remediation: {finding.remediation_advice}")
                if len(findings) > 5:
                    print(f"  ... and {len(findings) - 5} more findings.")
            print("-" * 65)

            formats_scan = config.output_formats if config.output_formats else ["terminal"]

            if config.output_path:
                out_path = Path(config.output_path)
                if "json" in formats_scan or out_path.suffix == ".json":
                    out_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
                    print(f"[+] Scan result (JSON) saved to: {out_path.resolve()}")
                else:
                    out_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
                    print(f"[+] Scan result saved to: {out_path.resolve()}")

                if "markdown" in formats_scan:
                    md_path = out_path.with_suffix(".md")
                    _write_scan_markdown(result, md_path)
                    print(f"[+] Scan report (Markdown) saved to: {md_path.resolve()}")

            return 0

    except Exception as exc:
        print(f"[-] Scan failed: {exc}", file=sys.stderr)
        if config.verbose:
            import traceback
            traceback.print_exc()
        return 1


def run_remediate(args) -> int:
    """Run the remediation pipeline."""
    import uuid as _uuid

    from auditor.core.config import ScanConfig
    from auditor.remediation import PatchGenerator, PatchValidator, RemediationReport
    from auditor.remediation.reporter import save_json_report, save_markdown_report, save_patch_files

    target = Path(args.target).resolve()
    if not target.exists() or not target.is_dir():
        print(f"[-] Target directory not found: {target}", file=sys.stderr)
        return 1

    output_dir = Path(args.output_dir) if args.output_dir else target / "remediation-output"
    offline = getattr(args, "offline", False)
    no_llm = getattr(args, "no_llm", False)
    validate = getattr(args, "validate", False)
    run_tests = getattr(args, "run_tests", False)
    finding_id_filter = getattr(args, "finding_id", None)
    formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    verbose = getattr(args, "verbose", False)
    scan_id = str(_uuid.uuid4())[:8]

    print("=" * 65)
    print(f" SYNTAXIS Remediation Engine v{__version__} [ID: {scan_id}]")
    print("=" * 65)
    print(f"[*] Target: {target}")
    print(f"[*] Mode: {'OFFLINE' if offline else 'ONLINE'} | LLM: {'Disabled' if no_llm else 'Enabled'}")
    print(f"[*] Validate: {validate} | Run-tests: {run_tests}")
    print("=" * 65)

    # Step 1 — Run a scan to get findings
    print("[1/4] Scanning for vulnerabilities...")
    scan_config = ScanConfig(
        target=str(target),
        offline_mode=offline,
        include_sast=True,
        include_deps=True,
        include_agents=False,  # agents not needed for remediation
        enable_llm=not no_llm,
    )

    try:
        from auditor.ingestion.factory import get_ingester
        from auditor.scanner.discovery import FileDiscoveryService
        from auditor.parser import ASTEngine
        from auditor.sast import SASTEngine
        from auditor.graph import CodeGraphService
        from auditor.dependencies import ManifestResolver, DependencyGraphService
        from auditor.advisories import OSVClient, normalize_advisories_to_findings

        ingester = get_ingester(str(target))
        with ingester.ingest(str(target)) as repo:
            discovery_service = FileDiscoveryService()
            disc = discovery_service.discover(repo.working_dir)
            repo_root = Path(repo.working_dir)

            findings = []
            manifest_rel_paths = [mf.relative_path for mf in disc.manifest_files]

            # SAST
            if disc.source_files:
                ast_engine = ASTEngine()
                parsed = ast_engine.parse_all(disc.source_files)
                sast_engine = SASTEngine()
                findings.extend(sast_engine.scan_all(parsed))

            # Deps
            if disc.manifest_files:
                resolver = ManifestResolver()
                dep_records = resolver.resolve_all(disc.manifest_files)
                resolved_queries = [
                    (r.ecosystem, r.normalized_name, r.version)
                    for r in dep_records if r.version
                ]
                unique_queries = list({(q[0], q[1], q[2]) for q in resolved_queries})
                if unique_queries:
                    osv_client = OSVClient(offline=offline)
                    query_results = osv_client.query_batch(unique_queries)
                    dep_findings = normalize_advisories_to_findings(query_results, dep_records)
                    findings.extend(dep_findings)

            print(f"[+] Found {len(findings)} finding(s) total.")

            # Filter to requested finding
            if finding_id_filter:
                matched = [f for f in findings if f.id == finding_id_filter]
                if not matched:
                    print(f"[-] Finding ID '{finding_id_filter}' not found in scan results.", file=sys.stderr)
                    return 1
                findings = matched
                print(f"[+] Filtered to finding: {finding_id_filter}")

            if not findings:
                print("[*] No findings to remediate. Saving empty report.")
                # Still save an empty report so tests and callers can verify the file
                report = RemediationReport(
                    scan_id=scan_id,
                    target=str(target),
                    metadata={"offline": offline, "no_llm": no_llm},
                )
                save_patch_files([], output_dir)
                if "json" in formats:
                    jp = save_json_report(report, output_dir / "reports")
                    print(f"[+] Report saved: {jp}")
                if "markdown" in formats:
                    mp = save_markdown_report(report, output_dir / "reports")
                    print(f"[+] Report saved: {mp}")
                return 0

            # Step 2 — Generate proposals
            print(f"[2/4] Generating patch proposals for {len(findings)} finding(s)...")
            generator = PatchGenerator(repo_root)
            proposals = generator.generate_all(findings, manifest_rel_paths)

            eligible = [p for p in proposals if p.unified_diff or p.proposed_content]
            unsupported_ids = [
                p.finding_id for p in proposals
                if not p.unified_diff and not p.proposed_content
            ]

            print(f"[+] Generated {len(eligible)} proposal(s), {len(unsupported_ids)} unsupported.")

            # Step 3 — Validate
            validation_results = []
            if validate and eligible:
                print(f"[3/4] Validating {len(eligible)} proposal(s) in isolated workspaces...")
                validator = PatchValidator(
                    repo_root=repo_root,
                    run_tests=run_tests,
                    run_sast_reanalysis=True,
                )
                for prop in eligible:
                    vr = validator.validate(prop)
                    validation_results.append(vr)
                    status_symbol = "[OK]" if vr.overall_status.value == "validated" else "[WARN]"
                    print(f"  {status_symbol} {prop.patch_id}: {vr.overall_status.value}")
            else:
                print("[3/4] Validation skipped (use --validate to enable).")

            # Step 4 — Save reports
            print("[4/4] Saving remediation reports...")
            report = RemediationReport(
                scan_id=scan_id,
                target=str(target),
                proposals=proposals,
                validation_results=validation_results,
                unsupported_finding_ids=unsupported_ids,
                metadata={
                    "offline": offline,
                    "no_llm": no_llm,
                    "validated": validate,
                    "run_tests": run_tests,
                },
            )

            # Save patch files
            save_patch_files(proposals, output_dir)

            saved_paths = []
            if "json" in formats:
                jp = save_json_report(report, output_dir / "reports")
                saved_paths.append(str(jp))
            if "markdown" in formats:
                mp = save_markdown_report(report, output_dir / "reports")
                saved_paths.append(str(mp))

            print("-" * 65)
            print(f"Proposals: {len(proposals)} | Eligible: {len(eligible)} | Unsupported: {len(unsupported_ids)}")
            for sp in saved_paths:
                print(f"[+] Report saved: {sp}")
            print("-" * 65)
            return 0

    except Exception as exc:
        print(f"[-] Remediation failed: {exc}", file=sys.stderr)
        if verbose:
            import traceback
            traceback.print_exc()
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
        config = ScanConfig(
            target=args.target,
            output_formats=formats,
            output_path=args.output,
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
        return run_scan(config)

    if args.command == "remediate":
        return run_remediate(args)

    if args.command == "evaluate":
        return run_evaluate(args)

    return 0


def run_evaluate(args) -> int:  # noqa: ANN001
    """Execute the benchmark evaluation workflow."""
    import datetime
    import uuid as _uuid

    from auditor.evaluation.dataset import (
        compute_manifest_hash,
        load_manifest,
        validate_dataset,
    )
    from auditor.evaluation.report import save_evaluation_json, save_evaluation_markdown
    from auditor.evaluation.runner import BenchmarkRunner, build_evaluation_run

    verbose = getattr(args, "verbose", False)
    offline = getattr(args, "offline", True)
    no_llm = getattr(args, "no_llm", True)
    dataset_path = getattr(args, "dataset", "benchmarks/manifest.json")
    output_dir = getattr(args, "output_dir", None)
    formats_raw = getattr(args, "format", "json,markdown")
    category_filter = getattr(args, "category", None)
    case_id_filter = getattr(args, "case_id", None)

    formats = [f.strip().lower() for f in formats_raw.split(",") if f.strip()]

    repo_root = Path(".").resolve()
    manifest_path = Path(dataset_path)
    if not manifest_path.is_absolute():
        manifest_path = repo_root / manifest_path

    print("=" * 65)
    print(f" SYNTAXIS Benchmark Evaluation v{__version__}")
    print("=" * 65)

    # Load and validate manifest
    try:
        cases, dataset_version, dataset_id = load_manifest(manifest_path)
    except FileNotFoundError as exc:
        print(f"[-] Dataset not found: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[-] Failed to load dataset: {exc}", file=sys.stderr)
        return 1

    errors = validate_dataset(cases, repo_root)
    if errors:
        print(f"[!] Dataset validation errors ({len(errors)}):")
        for e in errors:
            print(f"    - {e}")
        # Non-fatal: continue with valid cases

    dataset_hash = compute_manifest_hash(manifest_path)

    # Apply filters
    filtered_cases = cases
    if category_filter:
        filtered_cases = [c for c in filtered_cases if c.category == category_filter]
    if case_id_filter:
        filtered_cases = [c for c in filtered_cases if c.id == case_id_filter]

    print(f"[*] Dataset: {dataset_id} v{dataset_version} ({len(filtered_cases)} cases)")
    print(f"[*] Mode: {'OFFLINE' if offline else 'ONLINE'} | No-LLM: {no_llm}")
    if category_filter:
        print(f"[*] Category filter: {category_filter}")
    if case_id_filter:
        print(f"[*] Case ID filter: {case_id_filter}")
    print("-" * 65)

    # Run benchmark
    runner = BenchmarkRunner(
        repo_root=repo_root,
        offline=offline,
        no_llm=no_llm,
        category_filter=None,  # Already filtered above
        case_id_filter=None,
    )

    results = []
    for i, case in enumerate(filtered_cases, 1):
        if verbose:
            print(f"[{i}/{len(filtered_cases)}] Running case {case.id} ({case.category}, {case.label})...")
        result = runner.run_case(case)
        results.append(result)
        status_symbol = {"tp": "+", "tn": "+", "fp": "!", "fn": "!", "error": "E", "ambiguous": "~"}.get(result.status, "?")
        if verbose or result.status in ("error", "fp", "fn"):
            print(f"    [{status_symbol}] {case.id}: {result.status.upper()} "
                  f"({result.findings_count} findings, {result.duration_seconds:.3f}s)"
                  + (f" — {result.error}" if result.error else ""))

    # Build evaluation run record
    run_id = str(_uuid.uuid4())[:8]
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    run = build_evaluation_run(
        cases=filtered_cases,
        results=results,
        run_id=run_id,
        timestamp=timestamp,
        dataset_version=dataset_version,
        dataset_id=dataset_id,
        dataset_hash=dataset_hash,
        offline=offline,
        no_llm=no_llm,
    )

    # Print summary
    m = run.overall_metrics
    print("-" * 65)
    print(f"Evaluation complete: {len(results)} cases in {run.performance.get('total_seconds', 'N/A')}s")
    print(f"  TP={m.tp}  TN={m.tn}  FP={m.fp}  FN={m.fn}  "
          f"Ambiguous={m.ambiguous}  Errors={m.errors}")
    print(f"  Precision={m.precision}  Recall={m.recall}  F1={m.f1}  Accuracy={m.accuracy}")
    print("-" * 65)

    # Save reports
    if output_dir is None:
        out_dir = repo_root / "reports" / "evaluation"
    else:
        out_dir = Path(output_dir)

    saved = []
    if "json" in formats:
        jp = save_evaluation_json(run, out_dir)
        saved.append(str(jp))
    if "markdown" in formats:
        mp = save_evaluation_markdown(run, out_dir)
        saved.append(str(mp))

    for sp in saved:
        print(f"[+] Report saved: {sp}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

