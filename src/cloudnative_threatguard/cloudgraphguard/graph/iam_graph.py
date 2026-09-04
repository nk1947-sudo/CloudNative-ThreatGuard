"""
Directed IAM Attack-Path Graph.
Tracks nodes (Users, Roles, Groups, Policies, Resources) and edges (ASSUME_ROLE, HAS_PERMISSION, CAN_ACCESS).
Provides multi-hop pathfinding from initial principal to target assets.
"""

from typing import Dict, List, Any, Optional, Set
from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    label: str
    node_type: str  # "IAM_USER", "IAM_ROLE", "IAM_GROUP", "RESOURCE", "EKS_CLUSTER"
    arn: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str  # "ASSUME_ROLE", "HAS_PERMISSION", "CAN_ACCESS", "EKS_ACCESS"
    weight: float = 1.0
    evidence: Dict[str, Any] = Field(default_factory=dict)


class IAMDirectedGraph:
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self._adjacency: Dict[str, List[GraphEdge]] = {}

    def add_node(self, node: GraphNode):
        self.nodes[node.id] = node
        if node.id not in self._adjacency:
            self._adjacency[node.id] = []

    def add_edge(self, edge: GraphEdge):
        self.edges.append(edge)
        if edge.source not in self._adjacency:
            self._adjacency[edge.source] = []
        self._adjacency[edge.source].append(edge)

    def find_paths(self, start_id: str, target_id: str, max_depth: int = 5) -> List[List[GraphEdge]]:
        """Find all directed paths between two nodes up to max_depth."""
        if start_id not in self.nodes or target_id not in self.nodes:
            return []

        results: List[List[GraphEdge]] = []

        def dfs(current: str, target: str, path: List[GraphEdge], visited: Set[str], depth: int):
            if depth > max_depth:
                return
            if current == target and path:
                results.append(list(path))
                return

            visited.add(current)
            for edge in self._adjacency.get(current, []):
                if edge.target not in visited:
                    path.append(edge)
                    dfs(edge.target, target, path, visited, depth + 1)
                    path.pop()
            visited.remove(current)

        dfs(start_id, target_id, [], set(), 0)
        return results

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.model_dump() for n in self.nodes.values()],
            "edges": [e.model_dump() for e in self.edges],
        }
