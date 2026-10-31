"""Unit tests for Python and JavaScript dependency manifest parsing."""

import tempfile
import unittest
from pathlib import Path

from auditor.core.models import DiscoveredFile
from auditor.dependencies.models import DependencyScope, ResolutionStatus
from auditor.dependencies.npm_parser import parse_package_json, parse_package_lock_json
from auditor.dependencies.python_parser import (
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_pyproject_toml,
    parse_requirements_txt,
)
from auditor.dependencies.resolver import ManifestResolver


class TestDependencyParsers(unittest.TestCase):

    def test_requirements_txt_parsing(self):
        content = """
        # Core requirements
        requests==2.28.0
        urllib3>=1.26.0,<2.0.0
        flask~=2.0.1
        pytest # unpinned test runner
        django[argon2]==4.2.0 ; python_version >= '3.8'
        -r other.txt
        --extra-index-url https://pypi.org/simple
        """
        records = parse_requirements_txt(content, "requirements.txt")

        # Pinned requests
        req_p = next(r for r in records if r.name == "requests")
        self.assertEqual(req_p.normalized_name, "requests")
        self.assertEqual(req_p.version, "2.28.0")
        self.assertEqual(req_p.resolution_status, ResolutionStatus.RESOLVED)
        self.assertTrue(req_p.is_direct)

        # Range urllib3
        req_u = next(r for r in records if r.name == "urllib3")
        self.assertEqual(req_u.normalized_name, "urllib3")
        self.assertIsNone(req_u.version)
        self.assertEqual(req_u.resolution_status, ResolutionStatus.UNRESOLVED_CONSTRAINT)

        # Extras and environment markers: django[argon2]==4.2.0
        req_d = next(r for r in records if r.name == "django")
        self.assertEqual(req_d.version, "4.2.0")
        self.assertEqual(req_d.resolution_status, ResolutionStatus.RESOLVED)

    def test_pyproject_toml_parsing(self):
        content = """
        [project]
        name = "my-app"
        dependencies = [
            "requests>=2.25.0",
            "fastapi==0.95.0",
        ]

        [project.optional-dependencies]
        dev = [
            "pytest>=7.0.0",
            "black==23.1.0",
        ]
        """
        records = parse_pyproject_toml(content, "pyproject.toml")
        self.assertEqual(len(records), 4)

        fastapi = next(r for r in records if r.name == "fastapi")
        self.assertEqual(fastapi.version, "0.95.0")
        self.assertEqual(fastapi.scope, DependencyScope.PRODUCTION)

        pytest = next(r for r in records if r.name == "pytest")
        self.assertEqual(pytest.scope, DependencyScope.DEVELOPMENT)

    def test_poetry_lock_parsing(self):
        content = """
        [[package]]
        name = "urllib3"
        version = "1.26.5"
        category = "main"
        optional = false

        [[package]]
        name = "requests"
        version = "2.25.1"
        category = "main"
        optional = false

        [package.dependencies]
        urllib3 = ">=1.21.1,<1.27"
        """
        records = parse_poetry_lock(content, "poetry.lock")
        self.assertEqual(len(records), 2)

        reqs = next(r for r in records if r.name == "requests")
        self.assertEqual(reqs.version, "2.25.1")
        self.assertIn("urllib3", reqs.dependencies)

    def test_pipfile_lock_parsing(self):
        content = """{
            "_meta": {"hash": {"sha256": "123"}},
            "default": {
                "requests": {"version": "==2.28.1"}
            },
            "develop": {
                "flake8": {"version": "==6.0.0"}
            }
        }"""
        records = parse_pipfile_lock(content, "Pipfile.lock")
        self.assertEqual(len(records), 2)

        req = next(r for r in records if r.name == "requests")
        self.assertEqual(req.version, "2.28.1")
        self.assertEqual(req.scope, DependencyScope.PRODUCTION)

        flk = next(r for r in records if r.name == "flake8")
        self.assertEqual(flk.version, "6.0.0")
        self.assertEqual(flk.scope, DependencyScope.DEVELOPMENT)

    def test_package_json_parsing(self):
        content = """{
            "name": "sample-js-pkg",
            "dependencies": {
                "lodash": "^4.17.21",
                "express": "4.18.2"
            },
            "devDependencies": {
                "jest": "~29.5.0"
            }
        }"""
        records = parse_package_json(content, "package.json")
        self.assertEqual(len(records), 3)

        # Range constraint is not treated as resolved version
        lodash = next(r for r in records if r.name == "lodash")
        self.assertIsNone(lodash.version)
        self.assertEqual(lodash.constraint, "^4.17.21")
        self.assertEqual(lodash.resolution_status, ResolutionStatus.UNRESOLVED_CONSTRAINT)

        # Exact pin is resolved
        express = next(r for r in records if r.name == "express")
        self.assertEqual(express.version, "4.18.2")
        self.assertEqual(express.resolution_status, ResolutionStatus.RESOLVED)

    def test_package_lock_json_v2_v3_parsing(self):
        content = """{
            "name": "sample-pkg",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "sample-pkg"},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "dev": false
                },
                "node_modules/express": {
                    "version": "4.18.2",
                    "dependencies": {
                        "accepts": "~1.3.8"
                    }
                },
                "node_modules/accepts": {
                    "version": "1.3.8"
                }
            }
        }"""
        records = parse_package_lock_json(content, "package-lock.json")
        self.assertEqual(len(records), 3)

        lodash = next(r for r in records if r.name == "lodash")
        self.assertEqual(lodash.version, "4.17.21")
        self.assertEqual(lodash.resolution_status, ResolutionStatus.RESOLVED)

        express = next(r for r in records if r.name == "express")
        self.assertEqual(express.version, "4.18.2")
        self.assertIn("accepts", express.dependencies)

    def test_malformed_manifest_handled_gracefully(self):
        # Empty or garbage strings should not raise exceptions
        self.assertEqual(parse_package_json("{invalid json}", "package.json"), [])
        self.assertEqual(parse_package_lock_json("not json", "package-lock.json"), [])
        self.assertEqual(parse_pyproject_toml("invalid [[ toml", "pyproject.toml"), [])


if __name__ == "__main__":
    unittest.main()

