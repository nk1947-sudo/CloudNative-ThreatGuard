"""
ThreatGuard Workload and Process Investigation Engine.
Provides deep digital forensics on Kubernetes workloads:
- Pod security context & configuration posture
- Parent/child process execution tree reconstruction
- Socket connection audit trail
- Sensitive file access log
- Correlated risk score and active alert dossier
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

from cloudnative_threatguard.runtime.events import SecurityEvent, Severity
from .risk import RiskScoringEngine


@dataclass
class ProcessNode:
    pid: int
    ppid: int
    binary: str
    arguments: str
    timestamp: str
    user: str = "root"
    children: List["ProcessNode"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "binary": self.binary,
            "arguments": self.arguments,
            "timestamp": self.timestamp,
            "user": self.user,
            "children": [c.to_dict() for c in self.children]
        }


@dataclass
class WorkloadSecurityPosture:
    privileged: bool = False
    run_as_user: Optional[int] = None
    run_as_non_root: bool = False
    read_only_root_filesystem: bool = False
    allow_privilege_escalation: bool = True
    host_pid: bool = False
    host_network: bool = False
    host_ipc: bool = False
    capabilities_add: List[str] = field(default_factory=list)
    capabilities_drop: List[str] = field(default_factory=list)

    @classmethod
    def from_pod_spec(cls, pod_spec: Dict[str, Any]) -> "WorkloadSecurityPosture":
        spec = pod_spec.get("spec", pod_spec)
        pod_sc = spec.get("securityContext", {})
        containers = spec.get("containers", [])
        primary_c = containers[0] if containers else {}
        c_sc = primary_c.get("securityContext", {})

        caps = c_sc.get("capabilities", {})
        return cls(
            privileged=c_sc.get("privileged", False),
            run_as_user=c_sc.get("runAsUser", pod_sc.get("runAsUser")),
            run_as_non_root=c_sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot", False)),
            read_only_root_filesystem=c_sc.get("readOnlyRootFilesystem", False),
            allow_privilege_escalation=c_sc.get("allowPrivilegeEscalation", True),
            host_pid=spec.get("hostPID", False),
            host_network=spec.get("hostNetwork", False),
            host_ipc=spec.get("hostIPC", False),
            capabilities_add=caps.get("add", []),
            capabilities_drop=caps.get("drop", [])
        )


class WorkloadInvestigator:
    """
    Forensics and process tree investigation engine for Kubernetes workloads.
    """
    def __init__(self, risk_engine: Optional[RiskScoringEngine] = None):
        self.risk_engine = risk_engine or RiskScoringEngine()

    def investigate(
        self,
        namespace: str,
        pod_name: str,
        events: List[SecurityEvent],
        pod_spec: Optional[Dict[str, Any]] = None,
        container_image: str = "nginx:1.25-alpine"
    ) -> Dict[str, Any]:
        """
        Generates a comprehensive investigation dossier for a specific workload.
        """
        # Filter events for this specific workload
        workload_events = [
            e for e in events
            if (e.namespace == namespace or not e.namespace) and
               (e.pod == pod_name or not e.pod or pod_name in e.pod)
        ]

        # Extract security posture
        spec = pod_spec or {}
        posture = WorkloadSecurityPosture.from_pod_spec(spec)

        # Categorize telemetry
        process_history = []
        socket_connections = []
        file_access_log = []

        for ev in workload_events:
            ts = ev.timestamp or datetime.now(timezone.utc).isoformat()
            if ev.action in ["process_exec", "priv_escalation", "detected"] and ev.process:
                process_history.append({
                    "timestamp": ts,
                    "event_id": ev.event_id,
                    "process": ev.process,
                    "arguments": ev.metadata.get("arguments", ""),
                    "pid": ev.metadata.get("pid", 1000 + len(process_history)),
                    "ppid": ev.metadata.get("ppid", 1),
                    "rule": ev.detection_rule,
                    "technique": ev.mitre_technique
                })

            if ev.destination_ip or "connect" in ev.action.lower() or ev.mitre_tactic == "Command and Control":
                socket_connections.append({
                    "timestamp": ts,
                    "event_id": ev.event_id,
                    "process": ev.process,
                    "destination_ip": ev.destination_ip or ev.metadata.get("destination_ip", "unknown"),
                    "destination_port": ev.destination_port or ev.metadata.get("destination_port", 0),
                    "protocol": ev.metadata.get("protocol", "TCP"),
                    "direction": "OUTBOUND"
                })

            if "file" in ev.action.lower() or ev.mitre_tactic == "Credential Access" or ev.file_path:
                file_access_log.append({
                    "timestamp": ts,
                    "event_id": ev.event_id,
                    "process": ev.process,
                    "file_path": ev.file_path or ev.metadata.get("accessed_file", ev.metadata.get("file_path", "/var/run/secrets/token")),
                    "access_type": ev.metadata.get("flags", "READ"),
                    "technique": ev.mitre_technique
                })

        # Reconstruct process hierarchy
        process_tree = self.reconstruct_process_tree(process_history)

        # Evaluate risk score
        risk_ref = f"{namespace}/{pod_name}"
        risk_eval = self.risk_engine.evaluate_workload(
            events=workload_events,
            workload_ref=risk_ref,
            workload_spec=spec
        )

        return {
            "workload_ref": risk_ref,
            "namespace": namespace,
            "pod_name": pod_name,
            "container_image": container_image,
            "investigated_at": datetime.now(timezone.utc).isoformat(),
            "security_posture": asdict(posture),
            "risk_assessment": risk_eval.to_dict(),
            "telemetry_summary": {
                "total_events": len(workload_events),
                "process_executions": len(process_history),
                "socket_connections": len(socket_connections),
                "file_accesses": len(file_access_log)
            },
            "process_tree": [p.to_dict() for p in process_tree],
            "process_history": process_history,
            "socket_connections": socket_connections,
            "file_access_log": file_access_log,
            "active_alerts": [
                {
                    "event_id": e.event_id,
                    "severity": e.severity,
                    "rule": e.detection_rule,
                    "tactic": e.mitre_tactic,
                    "technique": e.mitre_technique,
                    "description": e.description
                }
                for e in workload_events if e.severity in [Severity.HIGH.value, Severity.CRITICAL.value]
            ]
        }

    def reconstruct_process_tree(self, process_records: List[Dict[str, Any]]) -> List[ProcessNode]:
        """
        Reconstructs parent-child process tree from chronological process records.
        """
        if not process_records:
            return []

        # Root container entrypoint
        root = ProcessNode(
            pid=1,
            ppid=0,
            binary="/pause" if "pause" in process_records[0].get("process", "") else "/entrypoint.sh",
            arguments="",
            timestamp=process_records[0].get("timestamp", ""),
            user="root"
        )

        node_map: Dict[int, ProcessNode] = {1: root}

        for rec in process_records:
            pid = rec.get("pid", 100)
            ppid = rec.get("ppid", 1)
            pnode = ProcessNode(
                pid=pid,
                ppid=ppid,
                binary=rec.get("process", ""),
                arguments=rec.get("arguments", ""),
                timestamp=rec.get("timestamp", ""),
                user="root"
            )
            node_map[pid] = pnode

            # Attach to parent if exists, else attach to root
            parent = node_map.get(ppid, root)
            parent.children.append(pnode)

        return [root]
