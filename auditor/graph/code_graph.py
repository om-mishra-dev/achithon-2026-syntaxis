"""Code relationship graph construction, symbol resolution, and call graph analysis using NetworkX."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set
import networkx as nx

from auditor.parser.models import ParsedFile


class CodeGraphService:
    """Constructs a directed graph of modules, classes, functions, and cross-file calls."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.unresolved_calls_count = 0
        self.resolved_calls_count = 0

    def build_graph(self, parsed_files: List[ParsedFile]) -> nx.DiGraph:
        self.graph.clear()
        self.unresolved_calls_count = 0
        self.resolved_calls_count = 0

        # Index functions and classes by name and by qualified path
        # function_index: short_name -> list of (node_id, file_path)
        func_index: Dict[str, List[tuple[str, str]]] = {}

        # 1. Add File, Class, and Function Nodes
        for pf in parsed_files:
            file_node_id = f"file:{pf.relative_path}"
            self.graph.add_node(
                file_node_id,
                node_type="FILE",
                path=pf.relative_path,
                language=pf.language,
                is_success=pf.is_success,
            )

            # Classes
            for cls in pf.classes:
                cls_node_id = f"class:{pf.relative_path}::{cls.name}"
                self.graph.add_node(
                    cls_node_id,
                    node_type="CLASS",
                    name=cls.name,
                    file=pf.relative_path,
                    start_line=cls.location.start_line,
                    bases=cls.bases,
                )
                self.graph.add_edge(file_node_id, cls_node_id, edge_type="CONTAINS")

            # Functions
            for fn in pf.functions:
                fn_node_id = f"func:{pf.relative_path}::{fn.qualified_name}"
                self.graph.add_node(
                    fn_node_id,
                    node_type="FUNCTION",
                    name=fn.name,
                    qualified_name=fn.qualified_name,
                    file=pf.relative_path,
                    start_line=fn.location.start_line,
                    parameters=fn.parameters,
                )
                self.graph.add_edge(file_node_id, fn_node_id, edge_type="CONTAINS")
                func_index.setdefault(fn.name, []).append((fn_node_id, pf.relative_path))

            # Imports
            for imp in pf.imports:
                imp_node_id = f"import:{pf.relative_path}::{imp.module}"
                self.graph.add_node(
                    imp_node_id,
                    node_type="IMPORT",
                    module=imp.module,
                    imported_names=imp.imported_names,
                    file=pf.relative_path,
                )
                self.graph.add_edge(file_node_id, imp_node_id, edge_type="IMPORTS")

        # 2. Add Calls and attempt cross-file / local resolution
        for pf in parsed_files:
            # Map imported symbols in this file to their source modules
            # e.g., "helper" -> "utils"
            imported_symbols: Dict[str, str] = {}
            for imp in pf.imports:
                for name in imp.imported_names:
                    imported_symbols[name] = imp.module

            for idx, call in enumerate(pf.calls):
                call_node_id = f"call:{pf.relative_path}::{call.callee_name}@{call.location.start_line}_{idx}"
                self.graph.add_node(
                    call_node_id,
                    node_type="CALL",
                    callee=call.callee_name,
                    file=pf.relative_path,
                    line=call.location.start_line,
                    arguments=call.arguments,
                )

                # Link caller function to call
                if call.enclosing_function:
                    caller_id = f"func:{pf.relative_path}::{call.enclosing_function}"
                    if self.graph.has_node(caller_id):
                        self.graph.add_edge(caller_id, call_node_id, edge_type="INVOKES")
                else:
                    self.graph.add_edge(f"file:{pf.relative_path}", call_node_id, edge_type="INVOKES")

                # Cross-reference resolution
                target_func_name = call.callee_name.split(".")[-1]
                candidates = func_index.get(target_func_name, [])

                resolved = False
                # Try matching by import or same-file definition
                for candidate_id, cand_file in candidates:
                    if cand_file == pf.relative_path:
                        self.graph.add_edge(call_node_id, candidate_id, edge_type="RESOLVES_TO")
                        resolved = True
                        break
                    elif target_func_name in imported_symbols:
                        # Candidate is imported
                        self.graph.add_edge(call_node_id, candidate_id, edge_type="RESOLVES_TO")
                        resolved = True
                        break

                if resolved:
                    self.resolved_calls_count += 1
                else:
                    self.unresolved_calls_count += 1

        return self.graph

    def to_dict(self) -> Dict[str, Any]:
        """Serialize code graph into a JSON-compatible dictionary."""
        nodes_list = []
        for node_id, data in self.graph.nodes(data=True):
            nodes_list.append({"id": node_id, **data})

        edges_list = []
        for u, v, data in self.graph.edges(data=True):
            edges_list.append({"source": u, "target": v, **data})

        return {
            "metrics": {
                "total_nodes": len(nodes_list),
                "total_edges": len(edges_list),
                "files_count": sum(1 for n in nodes_list if n.get("node_type") == "FILE"),
                "functions_count": sum(1 for n in nodes_list if n.get("node_type") == "FUNCTION"),
                "classes_count": sum(1 for n in nodes_list if n.get("node_type") == "CLASS"),
                "calls_count": sum(1 for n in nodes_list if n.get("node_type") == "CALL"),
                "resolved_calls": self.resolved_calls_count,
                "unresolved_calls": self.unresolved_calls_count,
            },
            "nodes": nodes_list,
            "edges": edges_list,
        }

