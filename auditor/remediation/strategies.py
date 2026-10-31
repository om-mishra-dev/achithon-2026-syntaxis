"""Patch generation strategies — strategy interface and all supported implementations."""

from __future__ import annotations

import difflib
import re
import uuid
from abc import ABC, abstractmethod
from typing import Optional

from auditor.remediation.models import (
    PatchProposal,
    PatchStatus,
    RemediationRequest,
    RemediationStrategy,
)


def _make_patch_id() -> str:
    return f"PATCH-{str(uuid.uuid4())[:8].upper()}"


def _unified_diff(original: str, patched: str, filename: str = "file") -> str:
    orig_lines = original.splitlines(keepends=True)
    new_lines = patched.splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(orig_lines, new_lines, fromfile=f"a/{filename}", tofile=f"b/{filename}")
    )


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------

class BaseStrategy(ABC):
    strategy_id: RemediationStrategy

    @abstractmethod
    def can_handle(self, request: RemediationRequest) -> bool:
        """Return True if this strategy applies to the request."""
        ...

    @abstractmethod
    def generate(self, request: RemediationRequest, original_content: str) -> PatchProposal:
        """Generate a PatchProposal for the given request and original file content."""
        ...


# ---------------------------------------------------------------------------
# Strategy A: SQL Injection → parameterized query
# ---------------------------------------------------------------------------

# Patterns to detect unsafe SQL construction on a single line
_SQL_FSTRING_RE = re.compile(
    r"""(?P<indent>\s*)(?P<obj>\w+)\.execute\(\s*(?P<quote>[fF]["'])(?P<body>[^'"]+)(?P=quote)\s*\)"""
)
_SQL_FORMAT_RE = re.compile(
    r"""(?P<indent>\s*)(?P<obj>\w+)\.execute\(\s*["'](?P<body>[^'"]+)["']\s*\.format\((?P<args>[^)]+)\)\s*\)"""
)
_SQL_CONCAT_RE = re.compile(
    r"""(?P<indent>\s*)(?P<obj>\w+)\.execute\(\s*["'](?P<body>[^'"]+)["']\s*\+\s*(?P<var>\w+)\s*\)"""
)

# Capture embedded Python expressions from f-string body: {expr}
_FEXPR_RE = re.compile(r'\{([^}]+)\}')


class SQLParameterizationStrategy(BaseStrategy):
    """Replace f-string / .format() / concatenation SQL with parameterized queries."""

    strategy_id = RemediationStrategy.SQL_PARAMETERIZATION

    def can_handle(self, request: RemediationRequest) -> bool:
        return (
            request.cwe_id == "CWE-89"
            and request.target_file is not None
            and request.target_file.endswith(".py")
            and request.source_excerpt is not None
        )

    def generate(self, request: RemediationRequest, original_content: str) -> PatchProposal:
        patch_id = _make_patch_id()
        warnings: list[str] = []

        patched, explanation, ok = self._rewrite(original_content, warnings)
        if not ok:
            return PatchProposal(
                patch_id=patch_id,
                finding_id=request.finding_id,
                strategy=RemediationStrategy.REVIEW_REQUIRED,
                status=PatchStatus.REQUIRES_REVIEW,
                target_file=request.target_file,
                explanation=(
                    "Could not automatically rewrite SQL query to use parameterized form. "
                    "Manual review required. " + (request.existing_remediation_advice or "")
                ),
                warnings=warnings,
                generated_by="deterministic",
            )

        diff = _unified_diff(original_content, patched, request.target_file or "file")
        return PatchProposal(
            patch_id=patch_id,
            finding_id=request.finding_id,
            strategy=self.strategy_id,
            status=PatchStatus.PROPOSED,
            target_file=request.target_file,
            original_content=original_content,
            proposed_content=patched,
            unified_diff=diff,
            explanation=explanation,
            warnings=warnings,
            evidence_references=[request.finding_id],
            generated_by="deterministic",
        )

    def _rewrite(self, content: str, warnings: list[str]) -> tuple[str, str, bool]:
        """Attempt to rewrite the first matching unsafe SQL pattern. Returns (new_content, explanation, success)."""
        lines = content.splitlines(keepends=True)
        new_lines = list(lines)
        changed = False

        for i, line in enumerate(lines):
            # Try f-string pattern
            m = _SQL_FSTRING_RE.search(line)
            if m:
                indent = m.group("indent")
                obj = m.group("obj")
                body = m.group("body")
                params = _FEXPR_RE.findall(body)
                if not params:
                    continue
                # Replace {expr} with %s placeholder
                safe_query = _FEXPR_RE.sub("%s", body)
                params_str = ", ".join(params)
                new_line = (
                    f"{indent}{obj}.execute(\n"
                    f"{indent}    \"{safe_query}\",\n"
                    f"{indent}    ({params_str},)\n"
                    f"{indent})\n"
                )
                new_lines[i] = new_line
                changed = True
                explanation = (
                    f"Line {i + 1}: Replaced f-string SQL with parameterized query "
                    f"using %s placeholders. Parameters: ({params_str},). "
                    f"Note: Verify placeholder style matches your database driver "
                    f"(sqlite3/%s, psycopg2/%s, pyodbc/?/?)."
                )
                warnings.append(
                    "Verify that %s placeholder is correct for your DB driver. "
                    "sqlite3, psycopg2 use %s; others may use ?."
                )
                break

            # Try .format() pattern
            m = _SQL_FORMAT_RE.search(line)
            if m:
                indent = m.group("indent")
                obj = m.group("obj")
                body = m.group("body")
                args = m.group("args")
                # Replace positional/keyword format holes with %s
                safe_query = re.sub(r'\{[^}]*\}', '%s', body)
                new_line = (
                    f"{indent}{obj}.execute(\n"
                    f"{indent}    \"{safe_query}\",\n"
                    f"{indent}    ({args},)\n"
                    f"{indent})\n"
                )
                new_lines[i] = new_line
                changed = True
                explanation = (
                    f"Line {i + 1}: Replaced .format() SQL with parameterized query. "
                    f"Verify placeholder style matches your DB driver."
                )
                warnings.append(
                    "Confirm parameter tuple ordering matches the original .format() arguments."
                )
                break

        if not changed:
            return content, "", False

        return "".join(new_lines), explanation, True


# ---------------------------------------------------------------------------
# Strategy B: Command Injection → argument list
# ---------------------------------------------------------------------------

_OSSYSTEM_RE = re.compile(
    r"""(?P<indent>\s*)os\.system\(\s*(?P<arg>[^\n]+?)\s*\)"""
)
_SUBPROCESS_SHELL_RE = re.compile(
    r"""(?P<indent>\s*)subprocess\.(?P<func>run|call|Popen|check_output)\(\s*(?P<arg>[^\n]+?),\s*shell\s*=\s*True"""
)


class CommandInjectionArglistStrategy(BaseStrategy):
    """Propose subprocess argument-list form for shell-based command execution."""

    strategy_id = RemediationStrategy.COMMAND_INJECTION_ARGLIST

    def can_handle(self, request: RemediationRequest) -> bool:
        return (
            request.cwe_id == "CWE-78"
            and request.target_file is not None
            and request.target_file.endswith(".py")
            and request.source_excerpt is not None
        )

    def generate(self, request: RemediationRequest, original_content: str) -> PatchProposal:
        patch_id = _make_patch_id()
        warnings: list[str] = []

        # os.system() calls: always require review — cannot split arbitrary shell commands safely
        if "os.system" in (original_content or ""):
            patched, ok = self._rewrite_os_system(original_content, warnings)
            if ok:
                diff = _unified_diff(original_content, patched, request.target_file or "file")
                return PatchProposal(
                    patch_id=patch_id,
                    finding_id=request.finding_id,
                    strategy=self.strategy_id,
                    status=PatchStatus.REQUIRES_REVIEW,
                    target_file=request.target_file,
                    original_content=original_content,
                    proposed_content=patched,
                    unified_diff=diff,
                    explanation=(
                        "os.system() replaced with subprocess.run() stub. "
                        "IMPORTANT: Review argument splitting carefully — do NOT blindly split "
                        "shell command strings. Verify the argument list preserves intended behavior."
                    ),
                    warnings=warnings,
                    evidence_references=[request.finding_id],
                    generated_by="deterministic",
                )

        # subprocess with shell=True: propose shell=False with review requirement
        if "shell=True" in (original_content or ""):
            patched, ok = self._rewrite_subprocess_shell(original_content, warnings)
            if ok:
                diff = _unified_diff(original_content, patched, request.target_file or "file")
                return PatchProposal(
                    patch_id=patch_id,
                    finding_id=request.finding_id,
                    strategy=self.strategy_id,
                    status=PatchStatus.REQUIRES_REVIEW,
                    target_file=request.target_file,
                    original_content=original_content,
                    proposed_content=patched,
                    unified_diff=diff,
                    explanation=(
                        "shell=True removed from subprocess call. "
                        "IMPORTANT: Pass arguments as a list, not a joined string. "
                        "Review that argument splitting is correct before applying."
                    ),
                    warnings=warnings,
                    evidence_references=[request.finding_id],
                    generated_by="deterministic",
                )

        return PatchProposal(
            patch_id=patch_id,
            finding_id=request.finding_id,
            strategy=RemediationStrategy.REVIEW_REQUIRED,
            status=PatchStatus.REQUIRES_REVIEW,
            target_file=request.target_file,
            explanation=(
                "Cannot safely auto-rewrite this command injection. "
                "Manual review required. " + (request.existing_remediation_advice or "")
            ),
            warnings=["Automated rewrite not possible — requires human review."],
            generated_by="deterministic",
        )

    def _rewrite_os_system(self, content: str, warnings: list[str]) -> tuple[str, bool]:
        if "import os" not in content and "from os" not in content:
            warnings.append("os module import not detected; add 'import subprocess' manually.")
        new = re.sub(
            r'\bos\.system\(([^)]+)\)',
            r'subprocess.run(\1, shell=False)  # REVIEW: split into argument list',
            content,
        )
        changed = new != content
        if changed:
            if "import subprocess" not in new:
                new = "import subprocess\n" + new
            warnings.append(
                "REVIEW REQUIRED: Do not pass a shell command string to subprocess.run() with shell=False. "
                "Replace with a list of arguments: subprocess.run(['cmd', 'arg1', ...])"
            )
        return new, changed

    def _rewrite_subprocess_shell(self, content: str, warnings: list[str]) -> tuple[str, bool]:
        new = re.sub(r',\s*shell\s*=\s*True', '', content)
        changed = new != content
        if changed:
            warnings.append(
                "REVIEW REQUIRED: With shell=False, the first argument must be a list, not a string. "
                "E.g. subprocess.run(['cmd', arg1, arg2])"
            )
        return new, changed


# ---------------------------------------------------------------------------
# Strategy C: Path Traversal → resolve + containment check
# ---------------------------------------------------------------------------

_OPEN_RE = re.compile(r"""(?P<indent>\s*)(?:with\s+)?open\(\s*(?P<path>[^\n,)]+)""")

_PATH_GUARD_TEMPLATE = """\
{indent}# PATH TRAVERSAL GUARD — review this block before deploying
{indent}_base = Path("{base_dir}")
{indent}_requested = Path({path_expr}).resolve()
{indent}if not str(_requested).startswith(str(_base.resolve())):
{indent}    raise ValueError(f"Path traversal detected: {{_requested}}")
"""


class PathTraversalValidationStrategy(BaseStrategy):
    """Insert a path-containment guard before unsafe open() calls."""

    strategy_id = RemediationStrategy.PATH_TRAVERSAL_VALIDATION

    def can_handle(self, request: RemediationRequest) -> bool:
        return (
            request.cwe_id == "CWE-22"
            and request.target_file is not None
            and request.target_file.endswith(".py")
            and request.source_excerpt is not None
        )

    def generate(self, request: RemediationRequest, original_content: str) -> PatchProposal:
        patch_id = _make_patch_id()
        warnings: list[str] = []
        patched, ok = self._insert_guard(original_content, warnings)

        if not ok:
            return PatchProposal(
                patch_id=patch_id,
                finding_id=request.finding_id,
                strategy=RemediationStrategy.REVIEW_REQUIRED,
                status=PatchStatus.REQUIRES_REVIEW,
                target_file=request.target_file,
                explanation=(
                    "Could not automatically locate open() call for path guard insertion. "
                    "Manually validate paths using Path.resolve() and check containment. "
                    + (request.existing_remediation_advice or "")
                ),
                warnings=warnings,
                generated_by="deterministic",
            )

        diff = _unified_diff(original_content, patched, request.target_file or "file")
        return PatchProposal(
            patch_id=patch_id,
            finding_id=request.finding_id,
            strategy=self.strategy_id,
            status=PatchStatus.REQUIRES_REVIEW,
            target_file=request.target_file,
            original_content=original_content,
            proposed_content=patched,
            unified_diff=diff,
            explanation=(
                "Inserted path-containment guard before open() call. "
                "IMPORTANT: Set the correct base directory constant and ensure "
                "Path is imported. Review before applying."
            ),
            warnings=warnings,
            evidence_references=[request.finding_id],
            generated_by="deterministic",
        )

    def _insert_guard(self, content: str, warnings: list[str]) -> tuple[str, bool]:
        lines = content.splitlines(keepends=True)
        for i, line in enumerate(lines):
            m = _OPEN_RE.search(line)
            if m:
                indent = m.group("indent")
                path_expr = m.group("path").strip()
                guard = _PATH_GUARD_TEMPLATE.format(
                    indent=indent,
                    base_dir="PERMITTED_BASE_DIR",
                    path_expr=path_expr,
                )
                if "from pathlib import Path" not in content and "import pathlib" not in content:
                    lines.insert(0, "from pathlib import Path\n")
                    i += 1
                lines.insert(i, guard)
                warnings.append(
                    "Replace 'PERMITTED_BASE_DIR' with the actual permitted directory. "
                    "Review guard logic carefully — os.path.basename() alone is NOT sufficient."
                )
                return "".join(lines), True
        return content, False


# ---------------------------------------------------------------------------
# Strategy D: Unsafe Deserialization → safe alternative
# ---------------------------------------------------------------------------

class SafeDeserializationStrategy(BaseStrategy):
    """Replace pickle.loads with JSON or yaml.load with yaml.safe_load."""

    strategy_id = RemediationStrategy.SAFE_DESERIALIZATION

    def can_handle(self, request: RemediationRequest) -> bool:
        return (
            request.cwe_id == "CWE-502"
            and request.target_file is not None
            and request.target_file.endswith(".py")
            and request.source_excerpt is not None
        )

    def generate(self, request: RemediationRequest, original_content: str) -> PatchProposal:
        patch_id = _make_patch_id()
        warnings: list[str] = []

        patched = original_content
        explanation_parts: list[str] = []
        changed = False

        # yaml.load → yaml.safe_load (safe; preserves behavior for safe input)
        if "yaml.load(" in patched:
            new = re.sub(r'\byaml\.load\(', 'yaml.safe_load(', patched)
            if new != patched:
                # Remove explicit Loader kwarg if present
                new = re.sub(r',\s*Loader\s*=\s*\w+', '', new)
                patched = new
                changed = True
                explanation_parts.append("yaml.load() replaced with yaml.safe_load().")

        # pickle.loads → requires review (JSON may not be compatible)
        if "pickle.loads(" in patched or "pickle.load(" in patched:
            warnings.append(
                "pickle.loads() cannot be safely replaced automatically. "
                "JSON is not compatible with arbitrary Python objects. "
                "Review the data format and use json.loads() only if data is JSON-compatible."
            )
            # Add a comment marker
            new = re.sub(
                r'\bpickle\.(loads?)\(',
                r'# UNSAFE: pickle.\1( — replace with json.loads() if data is JSON-compatible\n    pickle.\1(',
                patched,
            )
            if new != patched:
                patched = new
                changed = True
                explanation_parts.append(
                    "pickle.load/loads marked for review — do NOT ship without verifying safe alternative."
                )

        if not changed:
            return PatchProposal(
                patch_id=patch_id,
                finding_id=request.finding_id,
                strategy=RemediationStrategy.REVIEW_REQUIRED,
                status=PatchStatus.REQUIRES_REVIEW,
                target_file=request.target_file,
                explanation="Could not auto-patch deserialization. Manual review required.",
                warnings=warnings,
                generated_by="deterministic",
            )

        diff = _unified_diff(original_content, patched, request.target_file or "file")
        return PatchProposal(
            patch_id=patch_id,
            finding_id=request.finding_id,
            strategy=self.strategy_id,
            status=PatchStatus.REQUIRES_REVIEW if "pickle" in original_content else PatchStatus.PROPOSED,
            target_file=request.target_file,
            original_content=original_content,
            proposed_content=patched,
            unified_diff=diff,
            explanation=" ".join(explanation_parts),
            warnings=warnings,
            evidence_references=[request.finding_id],
            generated_by="deterministic",
        )


# ---------------------------------------------------------------------------
# Strategy E: Dependency remediation
# ---------------------------------------------------------------------------

_REQUIREMENTS_LINE_RE = re.compile(
    r'^(?P<pkg>[A-Za-z0-9_\-]+)\s*(?P<constraint>[><=!~][^\s#]*)?'
)
_PACKAGE_JSON_DEP_RE = re.compile(
    r'"(?P<pkg>[^"]+)"\s*:\s*"(?P<ver>[^"]+)"'
)


class DependencyVersionUpgradeStrategy(BaseStrategy):
    """Update manifest entry to a verified fixed version."""

    strategy_id = RemediationStrategy.DEPENDENCY_VERSION_UPGRADE

    def can_handle(self, request: RemediationRequest) -> bool:
        return (
            request.finding_type == "DEPENDENCY_VULNERABILITY"
            and request.package_name is not None
            and request.fixed_version is not None   # must have verified fixed version
            and request.manifest_file is not None
        )

    def generate(self, request: RemediationRequest, original_content: str) -> PatchProposal:
        patch_id = _make_patch_id()
        warnings: list[str] = []

        if not request.fixed_version:
            return PatchProposal(
                patch_id=patch_id,
                finding_id=request.finding_id,
                strategy=RemediationStrategy.REVIEW_REQUIRED,
                status=PatchStatus.REQUIRES_REVIEW,
                target_file=request.manifest_file,
                explanation=(
                    f"No verified fixed version available for {request.package_name}. "
                    "Cannot generate a safe upgrade proposal without confirmed advisory data."
                ),
                warnings=["Advisory does not specify a fixed version; upgrade manually."],
                generated_by="deterministic",
            )

        target_file = request.manifest_file or ""
        patched = original_content
        changed = False

        if target_file.endswith(".txt") or target_file.endswith(".txt"):
            # requirements.txt format
            patched, changed = self._patch_requirements(
                original_content, request.package_name, request.fixed_version, warnings
            )
        elif target_file.endswith("package.json"):
            patched, changed = self._patch_package_json(
                original_content, request.package_name, request.fixed_version, warnings
            )
        else:
            warnings.append(f"Unsupported manifest format: {target_file}")

        if not changed:
            return PatchProposal(
                patch_id=patch_id,
                finding_id=request.finding_id,
                strategy=RemediationStrategy.REVIEW_REQUIRED,
                status=PatchStatus.REQUIRES_REVIEW,
                target_file=target_file or request.manifest_file,
                explanation=f"Could not locate {request.package_name} in manifest for automated update.",
                warnings=warnings,
                generated_by="deterministic",
            )

        diff = _unified_diff(original_content, patched, target_file or "manifest")
        warnings.append(
            f"Verify that {request.package_name}>={request.fixed_version} is compatible "
            "with your other dependencies before applying."
        )
        return PatchProposal(
            patch_id=patch_id,
            finding_id=request.finding_id,
            strategy=self.strategy_id,
            status=PatchStatus.PROPOSED,
            target_file=target_file or request.manifest_file,
            original_content=original_content,
            proposed_content=patched,
            unified_diff=diff,
            explanation=(
                f"Updated {request.package_name} constraint to >={request.fixed_version} "
                f"based on advisory {request.advisory_id or 'data'}. "
                f"Fixed version source: verified advisory record (not guessed)."
            ),
            warnings=warnings,
            evidence_references=[request.finding_id],
            generated_by="deterministic",
        )

    def _patch_requirements(
        self, content: str, pkg: str, fixed_ver: str, warnings: list[str]
    ) -> tuple[str, bool]:
        lines = content.splitlines(keepends=True)
        new_lines = []
        changed = False
        pkg_normalized = pkg.lower().replace("-", "_").replace(".", "_")
        for line in lines:
            m = _REQUIREMENTS_LINE_RE.match(line.strip())
            if m:
                pkg_name = m.group("pkg").lower().replace("-", "_").replace(".", "_")
                if pkg_name == pkg_normalized:
                    new_lines.append(f"{pkg}>={fixed_ver}\n")
                    changed = True
                    continue
            new_lines.append(line)
        return "".join(new_lines), changed

    def _patch_package_json(
        self, content: str, pkg: str, fixed_ver: str, warnings: list[str]
    ) -> tuple[str, bool]:
        escaped = re.escape(pkg)
        pattern = re.compile(
            r'("' + escaped + r'"\s*:\s*")[^"]*(")'
        )
        new_content, count = pattern.subn(r'\g<1>^' + fixed_ver + r'\2', content)
        if count == 0:
            warnings.append(f"Package {pkg!r} not found in package.json.")
        return new_content, count > 0


# ---------------------------------------------------------------------------
# Unsupported fallback
# ---------------------------------------------------------------------------

class UnsupportedStrategy(BaseStrategy):
    """Fallback for unsupported vulnerability types."""

    strategy_id = RemediationStrategy.UNSUPPORTED

    def can_handle(self, request: RemediationRequest) -> bool:
        return True  # catch-all

    def generate(self, request: RemediationRequest, original_content: str) -> PatchProposal:
        return PatchProposal(
            patch_id=_make_patch_id(),
            finding_id=request.finding_id,
            strategy=self.strategy_id,
            status=PatchStatus.UNSUPPORTED,
            target_file=request.target_file or request.manifest_file,
            explanation=(
                f"Automated remediation is not supported for this finding type "
                f"(CWE: {request.cwe_id}, type: {request.finding_type}). "
                f"Manual remediation required. {request.existing_remediation_advice or ''}"
            ),
            warnings=["No automated strategy available; human review required."],
            generated_by="deterministic",
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALL_STRATEGIES: list[BaseStrategy] = [
    SQLParameterizationStrategy(),
    CommandInjectionArglistStrategy(),
    PathTraversalValidationStrategy(),
    SafeDeserializationStrategy(),
    DependencyVersionUpgradeStrategy(),
]

_FALLBACK = UnsupportedStrategy()


def get_strategy(request: RemediationRequest) -> BaseStrategy:
    for strategy in ALL_STRATEGIES:
        if strategy.can_handle(request):
            return strategy
    return _FALLBACK

