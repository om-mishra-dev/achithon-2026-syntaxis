"""Deterministic SAST engine with targeted source-to-sink data-flow analysis."""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from auditor.core.models import (
    CodeLocation,
    Confidence,
    EvidenceItem,
    Finding,
    FindingType,
    Severity,
)
from auditor.core.safety import redact_secrets
from auditor.parser.models import CallExpression, ParsedFile, SourceLocation, VariableAssignment
from .rules import RULES, SASTRule

# Recognized taint sources
TAINT_SOURCE_PATTERNS = [
    re.compile(r"\brequest\.(?:args|form|values|GET|POST|json|data)\b"),
    re.compile(r"\breq\.(?:query|body|params|headers)\b"),
    re.compile(r"\bsys\.argv\b"),
]

# Sanitizer patterns that neutralize taint
SANITIZER_PATTERNS = [
    re.compile(r"\bshlex\.quote\b"),
    re.compile(r"\bos\.path\.basename\b"),
    re.compile(r"\bint\("),
    re.compile(r"\bfloat\("),
    re.compile(r"\bis_safe_subpath\b"),
    re.compile(r"\bhtml\.escape\b"),
]


class TaintTracker:
    """Tracks local intra-procedural variable taint propagation."""

    def __init__(self, assignments: List[VariableAssignment]):
        self.tainted_vars: Dict[str, SourceLocation] = {}
        self.sanitized_vars: Set[str] = set()
        self.build_taint_table(assignments)

    def build_taint_table(self, assignments: List[VariableAssignment]) -> None:
        for assign in assignments:
            expr = assign.value_expr
            target = assign.target

            # 1. Check if sanitized
            if any(p.search(expr) for p in SANITIZER_PATTERNS):
                self.tainted_vars.pop(target, None)
                self.sanitized_vars.add(target)
                continue

            # 2. Check if direct source
            is_direct_source = any(p.search(expr) for p in TAINT_SOURCE_PATTERNS)
            if is_direct_source:
                self.tainted_vars[target] = assign.location
                self.sanitized_vars.discard(target)
                continue

            # 3. Check propagation from existing tainted variables
            is_prop = False
            for tainted_var, src_loc in list(self.tainted_vars.items()):
                if re.search(r"\b" + re.escape(tainted_var) + r"\b", expr):
                    self.tainted_vars[target] = src_loc
                    self.sanitized_vars.discard(target)
                    is_prop = True
                    break

            if not is_prop:
                for san_var in self.sanitized_vars:
                    if re.search(r"\b" + re.escape(san_var) + r"\b", expr):
                        self.sanitized_vars.add(target)
                        break

    def is_tainted(self, expr: str) -> Tuple[bool, Optional[SourceLocation]]:
        # Check direct source in expression
        if any(p.search(expr) for p in TAINT_SOURCE_PATTERNS):
            return True, None

        # Check if sanitized
        if any(p.search(expr) for p in SANITIZER_PATTERNS):
            return False, None

        # Check propagation from local variables
        for tainted_var, src_loc in self.tainted_vars.items():
            if re.search(r"\b" + re.escape(tainted_var) + r"\b", expr):
                return True, src_loc

        return False, None

    def is_sanitized(self, expr: str) -> bool:
        if any(p.search(expr) for p in SANITIZER_PATTERNS):
            return True
        for san_var in self.sanitized_vars:
            if re.search(r"\b" + re.escape(san_var) + r"\b", expr):
                return True
        return False


class SASTEngine:
    """Runs deterministic security checks and source-to-sink reachability analysis on parsed ASTs."""

    def __init__(self, rules: Dict[str, SASTRule] | None = None):
        self.rules = rules or RULES

    def scan_file(self, parsed_file: ParsedFile) -> List[Finding]:
        findings: List[Finding] = []
        if not parsed_file.is_success:
            return findings

        # Group assignments by enclosing function for local taint tracking
        func_assignments: Dict[Optional[str], List[VariableAssignment]] = {}
        for a in parsed_file.assignments:
            func_assignments.setdefault(a.enclosing_function, []).append(a)

        # Evaluate each call expression
        for call in parsed_file.calls:
            local_assignments = func_assignments.get(call.enclosing_function, [])
            tracker = TaintTracker(local_assignments)

            finding = self._evaluate_call(call, tracker, parsed_file)
            if finding:
                findings.append(finding)

        return findings

    def _evaluate_call(
        self,
        call: CallExpression,
        tracker: TaintTracker,
        parsed_file: ParsedFile,
    ) -> Optional[Finding]:
        callee = call.callee_name

        # 1. Check CWE-78: OS Command Injection
        rule_78 = self.rules["RULE-CWE-78"]
        if callee in rule_78.target_sinks:
            return self._check_command_injection(call, tracker, parsed_file, rule_78)

        # 2. Check CWE-89: SQL Injection
        rule_89 = self.rules["RULE-CWE-89"]
        if callee in rule_89.target_sinks or callee.endswith(".execute"):
            return self._check_sql_injection(call, tracker, parsed_file, rule_89)

        # 3. Check CWE-502: Unsafe Deserialization
        rule_502 = self.rules["RULE-CWE-502"]
        if callee in rule_502.target_sinks:
            return self._check_deserialization(call, tracker, parsed_file, rule_502)

        # 4. Check CWE-22: Path Traversal
        rule_22 = self.rules["RULE-CWE-22"]
        if callee in rule_22.target_sinks:
            return self._check_path_traversal(call, tracker, parsed_file, rule_22)

        # 5. Check CWE-79: XSS
        rule_79 = self.rules["RULE-CWE-79"]
        if callee in rule_79.target_sinks:
            return self._check_xss(call, tracker, parsed_file, rule_79)

        return None

    def _check_command_injection(
        self,
        call: CallExpression,
        tracker: TaintTracker,
        parsed_file: ParsedFile,
        rule: SASTRule,
    ) -> Optional[Finding]:
        if not call.arguments:
            return None

        first_arg = call.arguments[0]

        # For subprocess calls, check if shell=True is passed
        is_subprocess = "subprocess" in call.callee_name
        shell_arg = call.keywords.get("shell", "").lower()
        has_shell_true = shell_arg in ("true", "1")

        if is_subprocess and not has_shell_true:
            # Safe: subprocess with shell=False (default) passing argument list
            return None

        # Check if first_arg is a static literal string without dynamic formatting
        if re.match(r"^['\"][^'\"]*['\"]$", first_arg) and not first_arg.startswith(('f"', "f'")):
            return None

        # Check if argument has been sanitized (e.g. shlex.quote)
        if tracker.is_sanitized(first_arg):
            return None

        # Check if tainted or dynamic formatting
        is_tainted, src_loc = tracker.is_tainted(first_arg)
        is_dynamic = first_arg.startswith(('f"', "f'")) or " + " in first_arg or "%" in first_arg or ".format(" in first_arg

        if is_tainted or is_dynamic:
            conf = Confidence.CONFIRMED if is_tainted else Confidence.SUSPECTED
            return self._build_sast_finding(
                rule=rule,
                call=call,
                parsed_file=parsed_file,
                title=f"{rule.cwe_id}: Command Injection in {call.callee_name}",
                description=f"Command string '{redact_secrets(first_arg)}' constructed dynamically or from untrusted input.",
                confidence=conf,
                source_location=src_loc,
            )

        return None

    def _check_sql_injection(
        self,
        call: CallExpression,
        tracker: TaintTracker,
        parsed_file: ParsedFile,
        rule: SASTRule,
    ) -> Optional[Finding]:
        if not call.arguments:
            return None

        query_arg = call.arguments[0]

        # If static literal string without f-string prefix, safe!
        if re.match(r"^['\"][^'\"]*['\"]$", query_arg) and not query_arg.startswith(('f"', "f'")):
            return None

        # Check if sanitized
        if tracker.is_sanitized(query_arg):
            return None

        # Check if dynamic concatenation or formatting
        is_dynamic = (
            query_arg.startswith(('f"', "f'"))
            or " + " in query_arg
            or " % " in query_arg
            or ".format(" in query_arg
        )
        is_tainted, src_loc = tracker.is_tainted(query_arg)

        # If query is dynamic, check if parameters tuple was passed as 2nd argument
        has_param_tuple = len(call.arguments) >= 2

        if (is_tainted or is_dynamic) and not (not is_tainted and has_param_tuple):
            conf = Confidence.CONFIRMED if is_tainted else Confidence.SUSPECTED
            return self._build_sast_finding(
                rule=rule,
                call=call,
                parsed_file=parsed_file,
                title=f"{rule.cwe_id}: SQL Injection in {call.callee_name}",
                description=f"SQL query '{redact_secrets(query_arg)}' constructed with inline dynamic formatting rather than parameterization.",
                confidence=conf,
                source_location=src_loc,
            )

        return None

    def _check_deserialization(
        self,
        call: CallExpression,
        tracker: TaintTracker,
        parsed_file: ParsedFile,
        rule: SASTRule,
    ) -> Optional[Finding]:
        callee = call.callee_name
        if not call.arguments:
            return None

        arg = call.arguments[0]

        if "pickle" in callee:
            # All pickle.loads are inherently unsafe for untrusted input
            is_tainted, src_loc = tracker.is_tainted(arg)
            conf = Confidence.CONFIRMED if is_tainted else Confidence.SUSPECTED
            return self._build_sast_finding(
                rule=rule,
                call=call,
                parsed_file=parsed_file,
                title=f"{rule.cwe_id}: Insecure Deserialization via {callee}",
                description=f"Insecure deserialization using {callee} on argument '{redact_secrets(arg)}'.",
                confidence=conf,
                source_location=src_loc,
            )

        if "yaml.load" in callee:
            # Check Loader keyword
            loader = call.keywords.get("Loader", "")
            if "SafeLoader" not in loader:
                return self._build_sast_finding(
                    rule=rule,
                    call=call,
                    parsed_file=parsed_file,
                    title=f"{rule.cwe_id}: Unsafe YAML Deserialization",
                    description=f"yaml.load called without SafeLoader. Use yaml.safe_load() instead.",
                    confidence=Confidence.CONFIRMED,
                )

        return None

    def _check_path_traversal(
        self,
        call: CallExpression,
        tracker: TaintTracker,
        parsed_file: ParsedFile,
        rule: SASTRule,
    ) -> Optional[Finding]:
        if not call.arguments:
            return None
        path_arg = call.arguments[0]

        # Static string literal is safe
        if re.match(r"^['\"][^'\"]*['\"]$", path_arg) and not path_arg.startswith(('f"', "f'")):
            return None

        # Check if sanitized
        if tracker.is_sanitized(path_arg):
            return None

        is_tainted, src_loc = tracker.is_tainted(path_arg)
        if is_tainted:
            return self._build_sast_finding(
                rule=rule,
                call=call,
                parsed_file=parsed_file,
                title=f"{rule.cwe_id}: Path Traversal in {call.callee_name}",
                description=f"Untrusted input used in filesystem path operation '{redact_secrets(path_arg)}'.",
                confidence=Confidence.CONFIRMED,
                source_location=src_loc,
            )

        return None

    def _check_xss(
        self,
        call: CallExpression,
        tracker: TaintTracker,
        parsed_file: ParsedFile,
        rule: SASTRule,
    ) -> Optional[Finding]:
        if not call.arguments:
            return None
        html_arg = call.arguments[0]

        is_tainted, src_loc = tracker.is_tainted(html_arg)
        is_dynamic = html_arg.startswith(('f"', "f'")) or " + " in html_arg or ".format(" in html_arg

        if is_tainted or is_dynamic:
            return self._build_sast_finding(
                rule=rule,
                call=call,
                parsed_file=parsed_file,
                title=f"{rule.cwe_id}: Reflected XSS in {call.callee_name}",
                description=f"Dynamic HTML template rendered with unescaped input: '{redact_secrets(html_arg)}'.",
                confidence=Confidence.CONFIRMED if is_tainted else Confidence.SUSPECTED,
                source_location=src_loc,
            )

        return None

    def _build_sast_finding(
        self,
        rule: SASTRule,
        call: CallExpression,
        parsed_file: ParsedFile,
        title: str,
        description: str,
        confidence: Confidence,
        source_location: Optional[SourceLocation] = None,
    ) -> Finding:
        sink_loc = call.location.to_code_location()
        locations = [sink_loc]
        evidence_items = [
            EvidenceItem(
                source_type="SAST_SINK",
                description=f"Vulnerable sink execution '{call.callee_name}' in {parsed_file.relative_path}:{call.location.start_line}",
                location=sink_loc,
                raw_evidence={"arguments": call.arguments, "keywords": call.keywords},
            )
        ]

        if source_location:
            src_loc_model = source_location.to_code_location()
            locations.insert(0, src_loc_model)
            evidence_items.insert(
                0,
                EvidenceItem(
                    source_type="SAST_SOURCE",
                    description=f"Tainted input origin in {source_location.file_path}:{source_location.start_line}",
                    location=src_loc_model,
                ),
            )

        return Finding(
            id=f"SAST-{rule.cwe_id}-{parsed_file.relative_path}:{call.location.start_line}",
            title=title,
            description=description,
            severity=rule.severity,
            confidence=confidence,
            finding_type=FindingType.SAST_VULNERABILITY,
            cwe_id=rule.cwe_id,
            locations=locations,
            evidence=evidence_items,
            remediation_advice=rule.remediation_advice,
        )

    def scan_all(self, parsed_files: List[ParsedFile]) -> List[Finding]:
        all_findings: List[Finding] = []
        for pf in parsed_files:
            all_findings.extend(self.scan_file(pf))
        return all_findings
