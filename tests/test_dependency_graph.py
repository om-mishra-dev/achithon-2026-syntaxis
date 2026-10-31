"""Unit tests for NetworkX dependency graph construction, traversal, and cycle handling."""

import unittest
from auditor.dependencies.graph import DependencyGraphService
from auditor.dependencies.models import DependencyRecord, DependencyScope, ResolutionStatus


class TestDependencyGraph(unittest.TestCase):

    def test_graph_edge_direction_and_direct_enumeration(self):
        # A -> B -> C
        rec_a = DependencyRecord(
            name="pkg-a",
            normalized_name="pkg-a",
            ecosystem="PyPI",
            version="1.0.0",
            is_direct=True,
            source_manifest="requirements.txt",
            dependencies={"pkg-b": ">=2.0.0"},
            resolution_status=ResolutionStatus.RESOLVED,
        )
        rec_b = DependencyRecord(
            name="pkg-b",
            normalized_name="pkg-b",
            ecosystem="PyPI",
            version="2.0.0",
            is_direct=False,
            source_manifest="poetry.lock",
            dependencies={"pkg-c": "==3.0.0"},
            resolution_status=ResolutionStatus.RESOLVED,
        )
        rec_c = DependencyRecord(
            name="pkg-c",
            normalized_name="pkg-c",
            ecosystem="PyPI",
            version="3.0.0",
            is_direct=False,
            source_manifest="poetry.lock",
            resolution_status=ResolutionStatus.RESOLVED,
        )

        service = DependencyGraphService()
        graph = service.build_graph([rec_a, rec_b, rec_c])

        # Verify ROOT -> pkg-a
        self.assertTrue(graph.has_edge("ROOT", "pypi:pkg-a@1.0.0"))

        # Verify edge direction: pkg-a -> pkg-b -> pkg-c
        self.assertTrue(graph.has_edge("pypi:pkg-a@1.0.0", "pypi:pkg-b@2.0.0"))
        self.assertTrue(graph.has_edge("pypi:pkg-b@2.0.0", "pypi:pkg-c@3.0.0"))

        # Test direct dependency enumeration
        directs = service.get_direct_dependencies()
        self.assertEqual(len(directs), 1)
        self.assertEqual(directs[0]["normalized_name"], "pkg-a")

        # Test transitive traversal from pkg-a
        transitive_from_a = service.get_transitive_dependencies("pypi:pkg-a@1.0.0")
        self.assertIn("pypi:pkg-b@2.0.0", transitive_from_a)
        self.assertIn("pypi:pkg-c@3.0.0", transitive_from_a)

    def test_cycle_detection_without_crashing(self):
        # Cyclical: X -> Y -> X
        rec_x = DependencyRecord(
            name="pkg-x",
            normalized_name="pkg-x",
            ecosystem="npm",
            version="1.0.0",
            is_direct=True,
            source_manifest="package.json",
            dependencies={"pkg-y": "1.0.0"},
            resolution_status=ResolutionStatus.RESOLVED,
        )
        rec_y = DependencyRecord(
            name="pkg-y",
            normalized_name="pkg-y",
            ecosystem="npm",
            version="1.0.0",
            is_direct=False,
            source_manifest="package-lock.json",
            dependencies={"pkg-x": "1.0.0"},
            resolution_status=ResolutionStatus.RESOLVED,
        )

        service = DependencyGraphService()
        service.build_graph([rec_x, rec_y])

        cycles = service.detect_cycles()
        self.assertGreaterEqual(len(cycles), 1)

        # Transitive traversal does not hang on cycles
        desc_x = service.get_transitive_dependencies("npm:pkg-x@1.0.0")
        self.assertIn("npm:pkg-y@1.0.0", desc_x)

    def test_graph_serialization(self):
        rec = DependencyRecord(
            name="requests",
            normalized_name="requests",
            ecosystem="PyPI",
            version="2.28.0",
            is_direct=True,
            source_manifest="requirements.txt",
            resolution_status=ResolutionStatus.RESOLVED,
        )
        service = DependencyGraphService()
        service.build_graph([rec])
        serialized = service.to_dict()

        self.assertIn("metrics", serialized)
        self.assertIn("nodes", serialized)
        self.assertIn("edges", serialized)
        self.assertEqual(serialized["metrics"]["direct_dependencies_count"], 1)


if __name__ == "__main__":
    unittest.main()

