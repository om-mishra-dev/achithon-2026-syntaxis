"""Normalizer converting OSV advisory objects into canonical Finding models."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from auditor.core.models import (
    CodeLocation,
    Confidence,
    EvidenceItem,
    Finding,
    FindingType,
    Severity,
)
from auditor.dependencies.models import DependencyRecord
from .osv_client import OSVQueryResult


def parse_cvss_score(severity_list: List[Dict[str, Any]]) -> Optional[float]:
    """Extract CVSS score from OSV severity entries if present."""
    if not isinstance(severity_list, list):
        return None
    for entry in severity_list:
        if isinstance(entry, dict) and entry.get("type") in ("CVSS_V3", "CVSS_V2"):
            score_val = entry.get("score")
            # If score is a CVSS vector string like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            # we check if a numeric score is embedded or if database_specific provides it.
            if isinstance(score_val, (int, float)):
                return float(score_val)
    return None


def map_severity(vuln_data: Dict[str, Any]) -> Tuple[Severity, Optional[float]]:
    """Determine Severity and optional CVSS numeric score from advisory data."""
    # Check database_specific severity
    db_specific = vuln_data.get("database_specific", {})
    if isinstance(db_specific, dict):
        raw_sev = db_specific.get("severity", "")
        if isinstance(raw_sev, str):
            sev_upper = raw_sev.upper().strip()
            if "CRITICAL" in sev_upper:
                return Severity.CRITICAL, 9.5
            if "HIGH" in sev_upper:
                return Severity.HIGH, 7.5
            if "MODERATE" in sev_upper or "MEDIUM" in sev_upper:
                return Severity.MEDIUM, 5.5
            if "LOW" in sev_upper:
                return Severity.LOW, 2.5

    # Check ecosystem_specific
    eco_specific = vuln_data.get("ecosystem_specific", {})
    if isinstance(eco_specific, dict):
        eco_sev = eco_specific.get("severity", "")
        if isinstance(eco_sev, str):
            s = eco_sev.upper()
            if "CRITICAL" in s:
                return Severity.CRITICAL, 9.5
            if "HIGH" in s:
                return Severity.HIGH, 7.5
            if "MODERATE" in s or "MEDIUM" in s:
                return Severity.MEDIUM, 5.5
            if "LOW" in s:
                return Severity.LOW, 2.5

    # Check CVSS vector or score in severity list
    sev_list = vuln_data.get("severity", [])
    cvss = parse_cvss_score(sev_list)
    if cvss is not None:
        if cvss >= 9.0:
            return Severity.CRITICAL, cvss
        if cvss >= 7.0:
            return Severity.HIGH, cvss
        if cvss >= 4.0:
            return Severity.MEDIUM, cvss
        return Severity.LOW, cvss

    # Default if no score provided
    return Severity.MEDIUM, None


def extract_fixed_version_and_range(vuln_data: Dict[str, Any], pkg_name: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract known fixed version and affected range from OSV 'affected' section."""
    affected = vuln_data.get("affected", [])
    if not isinstance(affected, list):
        return None, None

    fixed_version: Optional[str] = None
    ranges_summary: List[str] = []

    for item in affected:
        if not isinstance(item, dict):
            continue
        p = item.get("package", {})
        if isinstance(p, dict) and p.get("name", "").lower() == pkg_name.lower():
            ranges = item.get("ranges", [])
            if isinstance(ranges, list):
                for r in ranges:
                    if not isinstance(r, dict):
                        continue
                    events = r.get("events", [])
                    introduced = None
                    fixed = None
                    for ev in events:
                        if isinstance(ev, dict):
                            if "introduced" in ev:
                                introduced = ev["introduced"]
                            if "fixed" in ev:
                                fixed = ev["fixed"]
                                if not fixed_version:
                                    fixed_version = fixed
                    if introduced or fixed:
                        rng_str = f">={introduced or '0'}"
                        if fixed:
                            rng_str += f", <{fixed}"
                        ranges_summary.append(rng_str)

    range_desc = " | ".join(ranges_summary) if ranges_summary else None
    return fixed_version, range_desc


def normalize_advisories_to_findings(
    query_results: List[OSVQueryResult],
    dependency_records: List[DependencyRecord],
) -> List[Finding]:
    """Convert query results and supporting manifest evidence into deduplicated Finding objects."""
    # Build lookup of package records by (ecosystem, normalized_name, version)
    records_map: Dict[Tuple[str, str, str], List[DependencyRecord]] = {}
    for rec in dependency_records:
        ver = rec.version or ""
        key = (rec.ecosystem.lower(), rec.normalized_name.lower(), ver)
        records_map.setdefault(key, []).append(rec)

    findings_by_key: Dict[str, Finding] = {}

    for q_res in query_results:
        if not q_res.advisories:
            continue

        key = (q_res.ecosystem.lower(), q_res.package_name.lower(), q_res.version)
        matching_records = records_map.get(key, [])

        for vuln in q_res.advisories:
            if not isinstance(vuln, dict):
                continue

            adv_id = vuln.get("id", "UNKNOWN-ADVISORY")
            finding_dedup_key = f"{q_res.ecosystem}:{q_res.package_name}:{q_res.version}:{adv_id}"

            # Extract CVE aliases
            aliases = vuln.get("aliases", [])
            cve_id = None
            if isinstance(aliases, list):
                for a in aliases:
                    if isinstance(a, str) and a.upper().startswith("CVE-"):
                        cve_id = a
                        break

            summary = vuln.get("summary") or vuln.get("details", "")[:120] or f"Vulnerability in {q_res.package_name}"
            details = vuln.get("details") or summary
            severity, cvss_score = map_severity(vuln)
            fixed_version, affected_range = extract_fixed_version_and_range(vuln, q_res.package_name)

            # Build locations and evidence from matching dependency records
            locations: List[CodeLocation] = []
            evidence_items: List[EvidenceItem] = []

            for rec in matching_records:
                loc = CodeLocation(
                    file_path=rec.source_manifest,
                    line=rec.declaration_line or 1,
                    snippet=f"{rec.name} {rec.constraint or rec.version or ''}".strip(),
                )
                locations.append(loc)
                evidence_items.append(
                    EvidenceItem(
                        source_type="MANIFEST_DECLARATION",
                        description=f"Declared in {rec.source_manifest} (scope: {rec.scope}, direct: {rec.is_direct})",
                        location=loc,
                        raw_evidence={
                            "manifest": rec.source_manifest,
                            "constraint": rec.constraint,
                            "resolved_version": rec.version,
                            "is_direct": rec.is_direct,
                        },
                    )
                )

            # Add OSV Advisory Evidence Item
            refs = [ref.get("url") for ref in vuln.get("references", []) if isinstance(ref, dict) and "url" in ref]
            evidence_items.append(
                EvidenceItem(
                    source_type="OSV_ADVISORY",
                    description=f"OSV Advisory {adv_id} (Aliases: {', '.join(aliases) if aliases else 'None'})",
                    raw_evidence={
                        "id": adv_id,
                        "aliases": aliases,
                        "published": vuln.get("published"),
                        "modified": vuln.get("modified"),
                        "affected_range": affected_range,
                        "fixed_version": fixed_version,
                    },
                )
            )

            # Remediation recommendation
            if fixed_version:
                remediation = f"Upgrade {q_res.package_name} to version {fixed_version} or higher."
            else:
                remediation = f"No fixed version documented in advisory {adv_id}. Consider replacing {q_res.package_name} or applying vendor workarounds."

            if finding_dedup_key in findings_by_key:
                # Merge locations and evidence
                existing = findings_by_key[finding_dedup_key]
                existing.locations.extend(locations)
                existing.evidence.extend(evidence_items)
            else:
                findings_by_key[finding_dedup_key] = Finding(
                    id=f"DEP-{adv_id}-{q_res.package_name}",
                    title=f"{adv_id}: {summary}",
                    description=details,
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    finding_type=FindingType.DEPENDENCY_VULNERABILITY,
                    cve_id=cve_id,
                    advisory_id=adv_id,
                    package_name=q_res.package_name,
                    ecosystem=q_res.ecosystem,
                    current_version=q_res.version,
                    fixed_version=fixed_version,
                    affected_range=affected_range,
                    cvss_score=cvss_score,
                    references=refs[:10],
                    locations=locations,
                    evidence=evidence_items,
                    remediation_advice=remediation,
                )

    return list(findings_by_key.values())

