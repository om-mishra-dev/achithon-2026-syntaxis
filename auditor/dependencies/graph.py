"""Dependency graph construction, traversal, cycle detection, and serialization using NetworkX."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set
import networkx as nx

from .models import DependencyRecord, DependencyScope, ResolutionStatus


class DependencyGraphService:
    """Builds and analyzes directed dependency graphs using NetworkX."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.is_relationship_data_complete = True

    @staticmethod
    def make_node_id(ecosystem: str, normalized_name: str, version: Optional[str] = None) -> str:
        eco = ecosystem.lower()
        if version:
            return f"{eco}:{normalized_name}@{version}"
        return f"{eco}:{normalized_name}"

    def build_graph(self, records: List[DependencyRecord]) -> nx.DiGraph:
        """Construct directed dependency graph from parsed DependencyRecords.
        
        Edge direction: dependent (parent) -> dependency (child).
        A special 'ROOT' node is created to point to direct dependencies.
        """
        self.graph.clear()
        self.graph.add_node("ROOT", node_type="root")
        
        # Map normalized name to node_id for parent-child resolution
        name_to_node_ids: Dict[str, List[str]] = {}
        has_child_dependencies = False

        # 1. Add all nodes
        for rec in records:
            node_id = self.make_node_id(rec.ecosystem, rec.normalized_name, rec.version)
            
            # Avoid overwriting a richer node attribute set with an unversioned one
            if not self.graph.has_node(node_id) or rec.version:
                self.graph.add_node(
                    node_id,
                    node_type="package",
                    ecosystem=rec.ecosystem,
                    name=rec.name,
                    normalized_name=rec.normalized_name,
                    version=rec.version,
                    constraint=rec.constraint,
                    is_direct=rec.is_direct,
                    scope=rec.scope.value if isinstance(rec.scope, DependencyScope) else str(rec.scope),
                    source_manifest=rec.source_manifest,
                    resolution_status=rec.resolution_status.value if isinstance(rec.resolution_status, ResolutionStatus) else str(rec.resolution_status),
                )

            name_to_node_ids.setdefault(rec.normalized_name, []).append(node_id)

            if rec.is_direct:
                self.graph.add_edge("ROOT", node_id, relationship="ROOT_TO_DIRECT", constraint=rec.constraint)

            if rec.dependencies:
                has_child_dependencies = True

        # 2. Add edges from declared dependencies in lockfiles
        for rec in records:
            parent_id = self.make_node_id(rec.ecosystem, rec.normalized_name, rec.version)
            for child_name, child_constraint in rec.dependencies.items():
                child_norm = child_name.lower()
                target_node_ids = name_to_node_ids.get(child_norm, [])

                if target_node_ids:
                    for target_id in target_node_ids:
                        if not self.graph.has_edge(parent_id, target_id):
                            self.graph.add_edge(
                                parent_id,
                                target_id,
                                relationship="DEPENDS_ON",
                                constraint=child_constraint,
                            )
                else:
                    # Incomplete target: child is mentioned in lockfile but not resolved
                    unresolved_id = self.make_node_id(rec.ecosystem, child_norm, None)
                    if not self.graph.has_node(unresolved_id):
                        self.graph.add_node(
                            unresolved_id,
                            node_type="package",
                            ecosystem=rec.ecosystem,
                            name=child_name,
                            normalized_name=child_norm,
                            version=None,
                            constraint=child_constraint,
                            is_direct=False,
                            scope=DependencyScope.UNKNOWN.value,
                            source_manifest=rec.source_manifest,
                            resolution_status=ResolutionStatus.UNRESOLVED_TRANSITIVE.value,
                        )
                    self.graph.add_edge(
                        parent_id,
                        unresolved_id,
                        relationship="DEPENDS_ON",
                        constraint=child_constraint,
                    )

        # Flag incomplete relationship info if manifest was flat (like requirements.txt without lockfile)
        if not has_child_dependencies and len(records) > 0:
            self.is_relationship_data_complete = False

        return self.graph

    def get_direct_dependencies(self) -> List[Dict[str, Any]]:
        """Return list of packages directly depended on by the project root."""
        if not self.graph.has_node("ROOT"):
            return []
        directs = []
        for successor in self.graph.successors("ROOT"):
            attrs = self.graph.nodes[successor]
            directs.append({"node_id": successor, **attrs})
        return directs

    def get_transitive_dependencies(self, node_id: str) -> Set[str]:
        """Safely traverse all reachable descendants from node_id, handling cycles."""
        if not self.graph.has_node(node_id):
            return set()
        try:
            return nx.descendants(self.graph, node_id)
        except Exception:
            return set()

    def detect_cycles(self) -> List[List[str]]:
        """Detect cyclic dependencies without crashing."""
        try:
            cycles = list(nx.simple_cycles(self.graph))
            # Filter out any trivial or root cycles
            return [c for c in cycles if "ROOT" not in c]
        except Exception:
            return []

    def to_dict(self) -> Dict[str, Any]:
        """Serialize dependency graph to a stable JSON-compatible dictionary."""
        nodes_list = []
        for node_id, data in self.graph.nodes(data=True):
            if node_id == "ROOT":
                continue
            nodes_list.append({"id": node_id, **data})

        edges_list = []
        for u, v, data in self.graph.edges(data=True):
            if u == "ROOT":
                continue
            edges_list.append({"source": u, "target": v, **data})

        cycles = self.detect_cycles()
        direct_deps = self.get_direct_dependencies()

        return {
            "metrics": {
                "total_package_nodes": len(nodes_list),
                "total_dependency_edges": len(edges_list),
                "direct_dependencies_count": len(direct_deps),
                "has_cycles": len(cycles) > 0,
                "cycle_count": len(cycles),
                "is_relationship_data_complete": self.is_relationship_data_complete,
            },
            "nodes": nodes_list,
            "edges": edges_list,
            "cycles": cycles,
        }

