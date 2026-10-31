"""AST Engine dispatcher for multi-language source code parsing."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from auditor.core.models import DiscoveredFile
from auditor.core.safety import is_safe_file_for_analysis
from .js_parser import parse_js_ts_source
from .models import ParsedFile
from .python_parser import parse_python_source


class ASTEngine:
    """Dispatches source files to their respective AST parsers."""

    def parse_file(self, file_info: DiscoveredFile) -> Optional[ParsedFile]:
        path = Path(file_info.path)
        is_safe, reason = is_safe_file_for_analysis(path)
        if not is_safe:
            return ParsedFile(
                file_path=file_info.path,
                relative_path=file_info.relative_path,
                language=file_info.language or "unknown",
                is_success=False,
                parse_error=reason,
            )

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception as err:
            return ParsedFile(
                file_path=file_info.path,
                relative_path=file_info.relative_path,
                language=file_info.language or "unknown",
                is_success=False,
                parse_error=f"File read error: {err}",
            )

        lang = (file_info.language or "").lower()

        try:
            if lang == "python":
                return parse_python_source(content, file_info.path, file_info.relative_path)
            elif lang in ("javascript", "typescript"):
                return parse_js_ts_source(content, file_info.path, file_info.relative_path, lang)
            else:
                return ParsedFile(
                    file_path=file_info.path,
                    relative_path=file_info.relative_path,
                    language=lang or "unknown",
                    is_success=False,
                    parse_error=f"Unsupported language: '{lang}'",
                )
        except Exception as err:
            return ParsedFile(
                file_path=file_info.path,
                relative_path=file_info.relative_path,
                language=lang or "unknown",
                is_success=False,
                parse_error=f"Unexpected parse exception: {err}",
            )

    def parse_all(self, source_files: List[DiscoveredFile]) -> List[ParsedFile]:
        """Parse all discovered source files, recording parse failures explicitly."""
        results: List[ParsedFile] = []
        for sf in source_files:
            parsed = self.parse_file(sf)
            if parsed:
                results.append(parsed)
        return results

