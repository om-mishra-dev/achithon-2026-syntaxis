"""Deterministic SAST rules with explicit CWE mappings, sink definitions, and remediation advice."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from auditor.core.models import Confidence, Severity


class SASTRule(BaseModel):
    rule_id: str
    cwe_id: str
    title: str
    description: str
    severity: Severity
    default_confidence: Confidence
    target_sinks: List[str]
    remediation_advice: str
    known_limitations: str


RULES: Dict[str, SASTRule] = {
    "RULE-CWE-78": SASTRule(
        rule_id="RULE-CWE-78",
        cwe_id="CWE-78",
        title="Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        description=(
            "Untrusted input is passed to an OS shell execution sink (e.g., os.system, "
            "subprocess.run with shell=True, or exec) without argument separation or validation."
        ),
        severity=Severity.CRITICAL,
        default_confidence=Confidence.CONFIRMED,
        target_sinks=["os.system", "subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_output", "exec", "eval"],
        remediation_advice="Pass command arguments as an array/list with shell=False (default), or use shlex.quote() for strict escaping.",
        known_limitations="Does not evaluate custom external sanitization wrapper functions.",
    ),
    "RULE-CWE-89": SASTRule(
        rule_id="RULE-CWE-89",
        cwe_id="CWE-89",
        title="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        description=(
            "A dynamically constructed query string (using f-strings, format, or string concatenation) "
            "is passed to a database execution sink without parameterization."
        ),
        severity=Severity.HIGH,
        default_confidence=Confidence.CONFIRMED,
        target_sinks=["cursor.execute", "connection.execute", "session.execute", "db.query", "client.query"],
        remediation_advice="Use parameterized queries (e.g., cursor.execute('SELECT * FROM t WHERE id = %s', (val,))) instead of inline string formatting.",
        known_limitations="Assumes first argument is SQL query; ORMs with query builders are not fully modeled.",
    ),
    "RULE-CWE-22": SASTRule(
        rule_id="RULE-CWE-22",
        cwe_id="CWE-22",
        title="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        description=(
            "User-supplied input is directly utilized in filesystem path operations (open, Path, etc.) "
            "without canonicalization or directory containment validation."
        ),
        severity=Severity.HIGH,
        default_confidence=Confidence.SUSPECTED,
        target_sinks=["open", "os.remove", "os.unlink", "shutil.rmtree", "pathlib.Path"],
        remediation_advice="Validate paths using Path.resolve() ensuring the target stays within the designated directory, or use os.path.basename().",
        known_limitations="Cannot verify if a path was validated in a separate helper function.",
    ),
    "RULE-CWE-502": SASTRule(
        rule_id="RULE-CWE-502",
        cwe_id="CWE-502",
        title="Deserialization of Untrusted Data",
        description=(
            "The application deserializes untrusted bytes using inherently dangerous deserialization "
            "APIs (e.g. pickle.loads, yaml.load without SafeLoader), leading to potential arbitrary code execution."
        ),
        severity=Severity.CRITICAL,
        default_confidence=Confidence.CONFIRMED,
        target_sinks=["pickle.loads", "pickle.load", "_pickle.loads", "yaml.load"],
        remediation_advice="Avoid pickle for untrusted input. Use safe data interchange formats like JSON or yaml.safe_load().",
        known_limitations="Does not inspect custom Unpickler subclasses that restrict globals.",
    ),
    "RULE-CWE-79": SASTRule(
        rule_id="RULE-CWE-79",
        cwe_id="CWE-79",
        title="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        description=(
            "Dynamic user input is rendered into HTML templates or HTTP response bodies without contextual escaping (e.g., render_template_string in Flask)."
        ),
        severity=Severity.MEDIUM,
        default_confidence=Confidence.CONFIRMED,
        target_sinks=["render_template_string", "res.send", "document.write"],
        remediation_advice="Use standard template files (render_template) where autoescaping is enabled by default, or HTML-escape variables.",
        known_limitations="Framework-specific autoescape contexts outside Flask/Jinja are partially detected.",
    ),
}

