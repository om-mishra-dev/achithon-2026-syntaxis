"""Client for querying the Open Source Vulnerabilities (OSV) database with caching and retries."""

from __future__ import annotations

import hashlib
import json
import os
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from auditor.dependencies.models import normalize_package_name

OSV_API_BASE = "https://api.osv.dev/v1"
OSV_QUERY_ENDPOINT = f"{OSV_API_BASE}/query"
OSV_BATCH_ENDPOINT = f"{OSV_API_BASE}/querybatch"

DEFAULT_TIMEOUT_SECONDS = 10
MAX_RETRIES = 3
INITIAL_BACKOFF_SECONDS = 0.5


class AdvisoryStatus(str, Enum):
    MATCHED = "MATCHED"
    NO_MATCH = "NO_MATCH"
    ERROR = "ERROR"
    UNAVAILABLE_OFFLINE = "UNAVAILABLE_OFFLINE"


class OSVQueryResult:
    def __init__(
        self,
        ecosystem: str,
        package_name: str,
        version: str,
        status: AdvisoryStatus,
        advisories: List[Dict[str, Any]] | None = None,
        error_message: Optional[str] = None,
        is_cached: bool = False,
    ):
        self.ecosystem = ecosystem
        self.package_name = package_name
        self.version = version
        self.status = status
        self.advisories = advisories or []
        self.error_message = error_message
        self.is_cached = is_cached

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "package_name": self.package_name,
            "version": self.version,
            "status": self.status.value,
            "advisories_count": len(self.advisories),
            "is_cached": self.is_cached,
            "error_message": self.error_message,
        }


class OSVClient:
    """Robust OSV API client with bounded retries, local caching, and offline support."""

    def __init__(
        self,
        cache_dir: Optional[str | Path] = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        offline: bool = False,
        session: Optional[requests.Session] = None,
    ):
        self.cache_dir = Path(cache_dir or Path(".auditor_cache") / "osv").resolve()
        self.timeout = timeout
        self.offline = offline
        self.session = session or requests.Session()

        # Ensure cache directory exists
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    @staticmethod
    def normalize_ecosystem(eco: str) -> str:
        """Map ecosystem string to official OSV ecosystem identifier."""
        e = eco.strip().lower()
        if e in ("pypi", "python"):
            return "PyPI"
        if e in ("npm", "javascript", "typescript"):
            return "npm"
        if e in ("crates.io", "rust"):
            return "crates.io"
        if e in ("go", "golang"):
            return "Go"
        return eco.strip()

    def _get_cache_key(self, ecosystem: str, normalized_name: str, version: str) -> str:
        raw_key = f"{ecosystem}::{normalized_name}::{version}"
        hashed = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        return f"{ecosystem}_{normalized_name}_{hashed[:12]}.json"

    def _read_from_cache(self, ecosystem: str, normalized_name: str, version: str) -> Optional[List[Dict[str, Any]]]:
        if not self.cache_dir.exists():
            return None
        cache_file = self.cache_dir / self._get_cache_key(ecosystem, normalized_name, version)
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                return data.get("vulns", [])
            except Exception:
                return None
        return None

    def _write_to_cache(self, ecosystem: str, normalized_name: str, version: str, vulns: List[Dict[str, Any]]) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file = self.cache_dir / self._get_cache_key(ecosystem, normalized_name, version)
            payload = {
                "ecosystem": ecosystem,
                "package": normalized_name,
                "version": version,
                "cached_at": time.time(),
                "vulns": vulns,
            }
            cache_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            pass

    def query_package_version(self, ecosystem: str, package_name: str, version: str) -> OSVQueryResult:
        """Query OSV for vulnerabilities affecting a specific package version."""
        norm_eco = self.normalize_ecosystem(ecosystem)
        norm_name = normalize_package_name(norm_eco, package_name)

        if not version or not version.strip():
            return OSVQueryResult(
                ecosystem=norm_eco,
                package_name=norm_name,
                version=version,
                status=AdvisoryStatus.ERROR,
                error_message="Cannot query advisory without a resolved package version",
            )

        # 1. Check local cache
        cached_vulns = self._read_from_cache(norm_eco, norm_name, version)
        if cached_vulns is not None:
            return OSVQueryResult(
                ecosystem=norm_eco,
                package_name=norm_name,
                version=version,
                status=AdvisoryStatus.MATCHED if cached_vulns else AdvisoryStatus.NO_MATCH,
                advisories=cached_vulns,
                is_cached=True,
            )

        # 2. Check offline mode
        if self.offline:
            return OSVQueryResult(
                ecosystem=norm_eco,
                package_name=norm_name,
                version=version,
                status=AdvisoryStatus.UNAVAILABLE_OFFLINE,
                error_message="Package not in local cache and offline mode is enabled",
                is_cached=False,
            )

        # 3. Query OSV API with exponential backoff retries
        body = {
            "package": {"name": norm_name, "ecosystem": norm_eco},
            "version": version,
        }

        retries = 0
        backoff = INITIAL_BACKOFF_SECONDS
        last_error = None

        while retries <= MAX_RETRIES:
            try:
                resp = self.session.post(
                    OSV_QUERY_ENDPOINT,
                    json=body,
                    timeout=self.timeout,
                    headers={"Content-Type": "application/json", "User-Agent": "Auditor-PS05/0.1.0"},
                )

                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulns", [])
                    # Cache successful response
                    self._write_to_cache(norm_eco, norm_name, version, vulns)
                    return OSVQueryResult(
                        ecosystem=norm_eco,
                        package_name=norm_name,
                        version=version,
                        status=AdvisoryStatus.MATCHED if vulns else AdvisoryStatus.NO_MATCH,
                        advisories=vulns,
                        is_cached=False,
                    )
                elif resp.status_code in (429, 500, 502, 503, 504):
                    last_error = f"HTTP {resp.status_code}: {resp.text[:100]}"
                    retries += 1
                    if retries <= MAX_RETRIES:
                        time.sleep(backoff)
                        backoff *= 2
                        continue
                else:
                    return OSVQueryResult(
                        ecosystem=norm_eco,
                        package_name=norm_name,
                        version=version,
                        status=AdvisoryStatus.ERROR,
                        error_message=f"HTTP {resp.status_code}: {resp.text[:100]}",
                    )

            except (requests.Timeout, requests.ConnectionError) as err:
                last_error = str(err)
                retries += 1
                if retries <= MAX_RETRIES:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
            except Exception as err:
                return OSVQueryResult(
                    ecosystem=norm_eco,
                    package_name=norm_name,
                    version=version,
                    status=AdvisoryStatus.ERROR,
                    error_message=f"Request failed: {err}",
                )

        return OSVQueryResult(
            ecosystem=norm_eco,
            package_name=norm_name,
            version=version,
            status=AdvisoryStatus.ERROR,
            error_message=f"Request failed after {MAX_RETRIES} retries: {last_error}",
        )

    def query_batch(
        self,
        package_queries: List[Tuple[str, str, str]],
    ) -> List[OSVQueryResult]:
        """Query multiple package versions, leveraging cache first, then batch querying the remainder.
        
        package_queries: List of (ecosystem, package_name, version)
        """
        results: List[OSVQueryResult] = []
        uncached_indices: List[int] = []
        batch_payload: List[Dict[str, Any]] = []

        # 1. First pass: consult cache
        for idx, (eco, name, ver) in enumerate(package_queries):
            norm_eco = self.normalize_ecosystem(eco)
            norm_name = normalize_package_name(norm_eco, name)

            if not ver:
                results.append(
                    OSVQueryResult(
                        ecosystem=norm_eco,
                        package_name=norm_name,
                        version="",
                        status=AdvisoryStatus.ERROR,
                        error_message="Cannot query advisory without resolved version",
                    )
                )
                continue

            cached = self._read_from_cache(norm_eco, norm_name, ver)
            if cached is not None:
                results.append(
                    OSVQueryResult(
                        ecosystem=norm_eco,
                        package_name=norm_name,
                        version=ver,
                        status=AdvisoryStatus.MATCHED if cached else AdvisoryStatus.NO_MATCH,
                        advisories=cached,
                        is_cached=True,
                    )
                )
            else:
                # Slot placeholder
                results.append(None)  # type: ignore
                uncached_indices.append(idx)
                batch_payload.append({
                    "package": {"name": norm_name, "ecosystem": norm_eco},
                    "version": ver,
                })

        # If everything was cached or offline, return immediately
        if not uncached_indices:
            return results

        if self.offline:
            for idx in uncached_indices:
                eco, name, ver = package_queries[idx]
                norm_eco = self.normalize_ecosystem(eco)
                norm_name = normalize_package_name(norm_eco, name)
                results[idx] = OSVQueryResult(
                    ecosystem=norm_eco,
                    package_name=norm_name,
                    version=ver,
                    status=AdvisoryStatus.UNAVAILABLE_OFFLINE,
                    error_message="Package not in cache (offline mode)",
                )
            return results

        # 2. Batch request to OSV
        try:
            resp = self.session.post(
                OSV_BATCH_ENDPOINT,
                json={"queries": batch_payload},
                timeout=self.timeout * 2,
                headers={"Content-Type": "application/json", "User-Agent": "Auditor-PS05/0.1.0"},
            )

            if resp.status_code == 200:
                data = resp.json()
                batch_results = data.get("results", [])

                for i, idx in enumerate(uncached_indices):
                    eco, name, ver = package_queries[idx]
                    norm_eco = self.normalize_ecosystem(eco)
                    norm_name = normalize_package_name(norm_eco, name)

                    vulns = []
                    if i < len(batch_results) and isinstance(batch_results[i], dict):
                        vulns = batch_results[i].get("vulns", [])

                    self._write_to_cache(norm_eco, norm_name, ver, vulns)
                    results[idx] = OSVQueryResult(
                        ecosystem=norm_eco,
                        package_name=norm_name,
                        version=ver,
                        status=AdvisoryStatus.MATCHED if vulns else AdvisoryStatus.NO_MATCH,
                        advisories=vulns,
                        is_cached=False,
                    )
            else:
                # Fallback to single queries if batch fails
                for idx in uncached_indices:
                    eco, name, ver = package_queries[idx]
                    results[idx] = self.query_package_version(eco, name, ver)

        except Exception as err:
            # Fallback to single queries
            for idx in uncached_indices:
                eco, name, ver = package_queries[idx]
                results[idx] = self.query_package_version(eco, name, ver)

        return results

