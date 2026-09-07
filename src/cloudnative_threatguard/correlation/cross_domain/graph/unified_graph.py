"""
Unified Security Graph Abstraction.
Represents cross-domain attack surfaces spanning Cloud IAM (CloudGraphGuard)
and Kubernetes runtime infrastructure (CloudNative ThreatGuard).
Preserves provenance and evidence for every edge.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class UnifiedNodeType(str, Enum):
    IAM_USER = "IAM_USER"
    IAM_ROLE = "IAM_ROLE"
    IAM_GROUP = "IAM_GROUP"
    AWS_ACCOUNT = "AWS_ACCOUNT"
    EKS_CLUSTER = "EKS_CLUSTER"
    K8S_SERVICE_ACCOUNT = "K8S_SERVICE_ACCOUNT"
    K8S_NAMESPACE = "K8S_NAMESPACE"
    K8S_DEPLOYMENT = "K8S_DEPLOYMENT"
    K8S_POD = "K8S_POD"
    CONTAINER = "CONTAINER"
    PROCESS = "PROCESS"
    SECRET = "SECRET"
    S3 = "S3"
    DATABASE = "DATABASE"
    RESOURCE = "RESOURCE"
    SECURITY_EVENT = "SECURITY_EVENT"
    INCIDENT = "INCIDENT"


class UnifiedRelationship(str, Enum):
    ASSUME_ROLE = "ASSUME_ROLE"
    HAS_PERMISSION = "HAS_PERMISSION"
    CAN_ACCESS = "CAN_ACCESS"
    CAN_ASSUME = "CAN_ASSUME"
    EKS_ACCESS = "EKS_ACCESS"
    MAPPED_TO = "MAPPED_TO"
    RUNS = "RUNS"
    CONTAINS = "CONTAINS"
    EXECUTED = "EXECUTED"
    TRIGGERED = "TRIGGERED"
    ACCESSED = "ACCESSED"
    DETECTED_BY = "DETECTED_BY"
    CORRELATED_WITH = "CORRELATED_WITH"


class UnifiedNode(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    label: str
    node_type: UnifiedNodeType
    source_system: str  # "CloudGraphGuard" or "CloudNative ThreatGuard"
    arn_or_uri: str | None = None
    severity: str | None = None
    risk_score: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class UnifiedEdge(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    source: str
    target: str
    relationship: UnifiedRelationship
    provenance: str = Field(description="Audit trail explaining why this edge exists")
    evidence: dict[str, Any] = Field(default_factory=dict)
    weight: float = 1.0


class UnifiedSecurityGraph:
    """
    Heterogeneous directed graph uniting Cloud IAM and Kubernetes runtime topologies.
    """

    def __init__(self):
        self.nodes: dict[str, UnifiedNode] = {}
        self.edges: list[UnifiedEdge] = []
        self._adjacency: dict[str, list[UnifiedEdge]] = {}

    def add_node(self, node: UnifiedNode):
        self.nodes[node.id] = node
        if node.id not in self._adjacency:
            self._adjacency[node.id] = []

    def add_edge(self, edge: UnifiedEdge):
        if edge.source not in self.nodes or edge.target not in self.nodes:
            raise ValueError(f"Cannot add edge {edge.source} -> {edge.target}: both nodes must exist in graph")
        self.edges.append(edge)
        self._adjacency[edge.source].append(edge)

    def find_attack_paths(self, start_id: str, target_id: str, max_depth: int = 8) -> list[list[UnifiedEdge]]:
        """DFS traversal finding all valid directed attack paths between nodes."""
        if start_id not in self.nodes or target_id not in self.nodes:
            return []

        paths: list[list[UnifiedEdge]] = []

        def dfs(curr: str, target: str, current_path: list[UnifiedEdge], visited: set[str], depth: int):
            if depth > max_depth:
                return
            if curr == target and current_path:
                paths.append(list(current_path))
                return

            visited.add(curr)
            for edge in self._adjacency.get(curr, []):
                if edge.target not in visited:
                    current_path.append(edge)
                    dfs(edge.target, target, current_path, visited, depth + 1)
                    current_path.pop()
            visited.remove(curr)

        dfs(start_id, target_id, [], set(), 0)
        return paths

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [n.model_dump() for n in self.nodes.values()],
            "edges": [e.model_dump() for e in self.edges],
        }

    def to_mermaid(self) -> str:
        """Generates Mermaid flowchart diagram highlighting cross-domain boundaries."""
        lines = ["flowchart TD"]
        # Node definitions
        for n in self.nodes.values():
            safe_id = n.id.replace(":", "_").replace("/", "_").replace("-", "_").replace(".", "_")
            source_tag = "CGG" if n.source_system == "CloudGraphGuard" else "TG"
            label = f'"{n.label}<br/>[{source_tag}: {n.node_type.value}]"'
            lines.append(f"    {safe_id}[{label}]")

        # Edge definitions
        for e in self.edges:
            s_id = e.source.replace(":", "_").replace("/", "_").replace("-", "_").replace(".", "_")
            t_id = e.target.replace(":", "_").replace("/", "_").replace("-", "_").replace(".", "_")
            lines.append(f"    {s_id} -->|{e.relationship.value}| {t_id}")

        # Styles
        lines.append("    classDef cggStyle fill:#4A154B,stroke:#9B51E0,stroke-width:2px,color:#FFFFFF;")
        lines.append("    classDef tgStyle fill:#1E293B,stroke:#EF4444,stroke-width:2px,color:#FFFFFF;")

        for n in self.nodes.values():
            safe_id = n.id.replace(":", "_").replace("/", "_").replace("-", "_").replace(".", "_")
            style = "cggStyle" if n.source_system == "CloudGraphGuard" else "tgStyle"
            lines.append(f"    class {safe_id} {style};")

        return "\n".join(lines)
