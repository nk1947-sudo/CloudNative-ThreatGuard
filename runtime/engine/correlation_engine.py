"""
Correlation and Detection Engine for CloudNative ThreatGuard.
Parses raw Tetragon eBPF telemetry, evaluates security detection rules,
enriches with MITRE ATT&CK metadata, and emits structured security alerts.
"""

import json
import os
import sys
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from .models import ThreatGuardDetection, SecurityEvent, SecurityIncident
from .rules import DETECTION_RULES

class ThreatGuardCorrelationEngine:
    def __init__(self, protected_namespace: str = "threatguard"):
        self.protected_namespace = protected_namespace
        self.rules = DETECTION_RULES
        self.detections: List[ThreatGuardDetection] = []
        self.total_events_processed: int = 0

    def process_raw_tetragon_event(self, raw_event: Dict[str, Any], record: bool = True) -> Optional[ThreatGuardDetection]:
        """
        Evaluates a single raw Tetragon event against detection rules.
        """
        self.total_events_processed += 1
        det = self._evaluate_raw_event(raw_event)
        if det and record:
            self.detections.append(det)
        return det

    def process_event(self, raw_event: Dict[str, Any], record: bool = True) -> Optional[ThreatGuardDetection]:
        """Convenience alias for process_raw_tetragon_event."""
        return self.process_raw_tetragon_event(raw_event, record=record)

    def _evaluate_raw_event(self, raw_event: Dict[str, Any]) -> Optional[ThreatGuardDetection]:

        # Tetragon events usually wrap process_exec, process_kprobe, etc.
        event_time = raw_event.get("time", datetime.now(timezone.utc).isoformat())

        # Extract process exec event
        exec_event = raw_event.get("process_exec")
        kprobe_event = raw_event.get("process_kprobe")

        if exec_event:
            return self._handle_process_exec(exec_event, event_time)
        elif kprobe_event:
            return self._handle_kprobe(kprobe_event, event_time)
        
        # In case an event has direct flat keys (simulation format)
        if "binary" in raw_event or "process" in raw_event:
            return self._handle_generic_event(raw_event, event_time)

        return None

    def _handle_process_exec(self, exec_event: Dict[str, Any], event_time: str) -> Optional[ThreatGuardDetection]:
        if not isinstance(exec_event, dict):
            return None
        proc = exec_event.get("process") or {}
        if not isinstance(proc, dict):
            return None
        binary = proc.get("binary") or ""
        args = proc.get("arguments") or ""
        pod = proc.get("pod") or {}
        if not isinstance(pod, dict):
            return None
        namespace = pod.get("namespace") or ""
        pod_name = pod.get("name") or ""
        container_obj = pod.get("container") or {}
        container = container_obj.get("name", "") if isinstance(container_obj, dict) else ""

        # Target contextual filtering: filter for protected namespace if specified
        if self.protected_namespace and namespace != self.protected_namespace:
            return None

        basename = os.path.basename(binary).lower()

        # RUNTIME-001: Shell execution
        if basename in ["sh", "bash", "dash", "zsh"]:
            rule = self.rules["RUNTIME-001"]
            return ThreatGuardDetection(
                timestamp=event_time,
                namespace=namespace or self.protected_namespace,
                pod=pod_name,
                container=container,
                process=binary,
                command=f"{binary} {args}".strip(),
                event_type=rule["event_type"],
                severity=rule["severity"],
                detection_name=rule["detection_name"],
                rule_id=rule["rule_id"],
                technique=rule["technique"],
                technique_name=rule["technique_name"],
                evidence={
                    "binary": binary,
                    "arguments": args,
                    "pid": proc.get("pid"),
                    "uid": proc.get("uid"),
                    "parent_process": proc.get("parent", {}).get("binary", "")
                }
            )

        # RUNTIME-002: Network utility
        if basename in ["curl", "wget", "nc", "netcat", "socat", "nmap"]:
            rule = self.rules["RUNTIME-002"]
            return ThreatGuardDetection(
                timestamp=event_time,
                namespace=namespace or self.protected_namespace,
                pod=pod_name,
                container=container,
                process=binary,
                command=f"{binary} {args}".strip(),
                event_type=rule["event_type"],
                severity=rule["severity"],
                detection_name=rule["detection_name"],
                rule_id=rule["rule_id"],
                technique=rule["technique"],
                technique_name=rule["technique_name"],
                evidence={
                    "binary": binary,
                    "arguments": args,
                    "pid": proc.get("pid"),
                    "parent_process": proc.get("parent", {}).get("binary", "")
                }
            )

        # RUNTIME-003: Reconnaissance
        if basename in ["whoami", "id", "uname", "ps", "env"]:
            rule = self.rules["RUNTIME-003"]
            return ThreatGuardDetection(
                timestamp=event_time,
                namespace=namespace or self.protected_namespace,
                pod=pod_name,
                container=container,
                process=binary,
                command=f"{binary} {args}".strip(),
                event_type=rule["event_type"],
                severity=rule["severity"],
                detection_name=rule["detection_name"],
                rule_id=rule["rule_id"],
                technique=rule["technique"],
                technique_name=rule["technique_name"],
                evidence={
                    "binary": binary,
                    "arguments": args,
                    "pid": proc.get("pid")
                }
            )

        # RUNTIME-005: Privilege escalation indicator
        if basename in ["nsenter", "unshare", "capsh", "chroot"]:
            rule = self.rules["RUNTIME-005"]
            return ThreatGuardDetection(
                timestamp=event_time,
                namespace=namespace or self.protected_namespace,
                pod=pod_name,
                container=container,
                process=binary,
                command=f"{binary} {args}".strip(),
                event_type=rule["event_type"],
                severity=rule["severity"],
                detection_name=rule["detection_name"],
                rule_id=rule["rule_id"],
                technique=rule["technique"],
                technique_name=rule["technique_name"],
                evidence={
                    "binary": binary,
                    "arguments": args,
                    "pid": proc.get("pid"),
                    "cap_effective": proc.get("cap", {}).get("effective", [])
                }
            )

        return None

    def _handle_kprobe(self, kprobe_event: Dict[str, Any], event_time: str) -> Optional[ThreatGuardDetection]:
        if not isinstance(kprobe_event, dict):
            return None
        func_name = kprobe_event.get("function_name") or ""
        proc = kprobe_event.get("process") or {}
        if not isinstance(proc, dict):
            return None
        pod = proc.get("pod") or {}
        if not isinstance(pod, dict):
            return None
        namespace = pod.get("namespace") or ""
        pod_name = pod.get("name") or ""
        container_obj = pod.get("container") or {}
        container = container_obj.get("name", "") if isinstance(container_obj, dict) else ""
        args_list = kprobe_event.get("args") or []
        if not isinstance(args_list, list):
            args_list = []

        if self.protected_namespace and namespace != self.protected_namespace:
            return None

        # RUNTIME-004: Sensitive file access via security_file_open or openat
        if "file" in func_name or "open" in func_name:
            file_path = ""
            for arg in args_list:
                if isinstance(arg, dict) and "file_arg" in arg:
                    file_path = arg.get("file_arg", {}).get("path", "")
                elif isinstance(arg, dict) and "string_arg" in arg:
                    file_path = arg.get("string_arg", "")

            sensitive_targets = [
                "/var/run/secrets/kubernetes.io/serviceaccount/token",
                "/etc/shadow",
                "/etc/gshadow",
                "/root/.ssh"
            ]
            for target in sensitive_targets:
                if file_path and (file_path == target or file_path.startswith(target)):
                    rule = self.rules["RUNTIME-004"]
                    return ThreatGuardDetection(
                        timestamp=event_time,
                        namespace=namespace or self.protected_namespace,
                        pod=pod_name,
                        container=container,
                        process=proc.get("binary", ""),
                        command=f"read {file_path}",
                        event_type=rule["event_type"],
                        severity=rule["severity"],
                        detection_name=rule["detection_name"],
                        rule_id=rule["rule_id"],
                        technique=rule["technique"],
                        technique_name=rule["technique_name"],
                        evidence={
                            "accessed_file": file_path,
                            "process": proc.get("binary", ""),
                            "syscall": func_name
                        }
                    )

        # RUNTIME-006: Outbound network connect
        if "connect" in func_name:
            sock_info = {}
            for arg in args_list:
                if isinstance(arg, dict) and "sock_arg" in arg:
                    sock_info = arg.get("sock_arg", {})

            rule = self.rules["RUNTIME-006"]
            return ThreatGuardDetection(
                timestamp=event_time,
                namespace=namespace or self.protected_namespace,
                pod=pod_name,
                container=container,
                process=proc.get("binary", ""),
                command=f"connect {sock_info.get('daddr', 'unknown')}:{sock_info.get('dport', '')}",
                event_type=rule["event_type"],
                severity=rule["severity"],
                detection_name=rule["detection_name"],
                rule_id=rule["rule_id"],
                technique=rule["technique"],
                technique_name=rule["technique_name"],
                evidence={
                    "destination_ip": sock_info.get("daddr", ""),
                    "destination_port": sock_info.get("dport", ""),
                    "protocol": sock_info.get("proto", "TCP"),
                    "process": proc.get("binary", "")
                }
            )

        return None

    def _handle_generic_event(self, event: Dict[str, Any], event_time: str) -> Optional[ThreatGuardDetection]:
        # Formatted test/simulation event ingestion
        rule_id = event.get("rule_id")
        if rule_id and rule_id in self.rules:
            rule = self.rules[rule_id]
            return ThreatGuardDetection(
                timestamp=event_time,
                namespace=event.get("namespace", self.protected_namespace),
                pod=event.get("pod", "simulated-target"),
                container=event.get("container", "app"),
                process=event.get("process", event.get("binary", "")),
                command=event.get("command", ""),
                event_type=rule["event_type"],
                severity=rule["severity"],
                detection_name=rule["detection_name"],
                rule_id=rule["rule_id"],
                technique=rule["technique"],
                technique_name=rule["technique_name"],
                evidence=event.get("evidence", {})
            )
        return None

    def ingest_file(self, filepath: str) -> List[ThreatGuardDetection]:
        """
        Parses a file containing line-delimited JSON events.
        """
        new_detections = []
        if not os.path.exists(filepath):
            return new_detections

        lines = []
        for enc in ["utf-8-sig", "utf-16", "utf-8", "latin-1"]:
            try:
                with open(filepath, "r", encoding=enc) as f:
                    lines = f.readlines()
                break
            except (UnicodeDecodeError, UnicodeError):
                continue

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                det = self.process_raw_tetragon_event(event, record=False)
                if det:
                    self.detections.append(det)
                    new_detections.append(det)
            except json.JSONDecodeError:
                continue
        return new_detections

    def get_summary(self) -> Dict[str, Any]:
        """
        Generates summary metrics for the telemetry scorecard.
        """
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        by_rule = {}
        by_technique = {}

        for d in self.detections:
            by_severity[d.severity] = by_severity.get(d.severity, 0) + 1
            by_rule[d.rule_id] = by_rule.get(d.rule_id, 0) + 1
            by_technique[d.technique] = by_technique.get(d.technique, 0) + 1

        return {
            "total_detections": len(self.detections),
            "total_events_processed": self.total_events_processed,
            "by_severity": by_severity,
            "by_rule": by_rule,
            "by_technique": by_technique
        }

    def correlate_incidents(
        self,
        events: Optional[List[SecurityEvent]] = None,
        window_seconds: int = 300
    ) -> List[SecurityIncident]:
        """
        Groups sequential security events by pod/workload into high-level attack chain incidents.
        Generates unique '#TG-xxxxxx' incident identifiers with combined tactics, techniques,
        and maximum severity.
        """
        target_events: List[SecurityEvent] = []
        if events is not None:
            target_events = events
        else:
            target_events = [d.to_security_event() for d in self.detections]

        if not target_events:
            return []

        # Group events by workload key: (namespace, pod)
        grouped: Dict[str, List[SecurityEvent]] = {}
        for ev in target_events:
            key = f"{ev.namespace}/{ev.pod}" if ev.pod else ev.namespace
            grouped.setdefault(key, []).append(ev)

        incidents: List[SecurityIncident] = []
        for key, ev_list in grouped.items():
            if not ev_list:
                continue

            # Sort events by timestamp
            ev_list.sort(key=lambda x: x.timestamp)

            # Determine aggregate severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)
            severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            highest_sev = "LOW"
            for e in ev_list:
                if e.severity in severity_order:
                    if severity_order.index(e.severity) > severity_order.index(highest_sev):
                        highest_sev = e.severity

            # Collect unique tactics and techniques preserving order
            tactics = []
            techniques = []
            for e in ev_list:
                if e.mitre_tactic and e.mitre_tactic not in tactics:
                    tactics.append(e.mitre_tactic)
                if e.mitre_technique and e.mitre_technique not in techniques:
                    techniques.append(e.mitre_technique)

            primary_ev = ev_list[0]
            pod_name = primary_ev.pod or key.split("/")[-1]
            ns_name = primary_ev.namespace or "threatguard"

            # Formulate incident title and summary
            if len(tactics) > 1:
                title = f"Multi-Stage Attack Chain Detected on {pod_name}"
                summary = (
                    f"Correlated {len(ev_list)} security events across {len(tactics)} MITRE tactics "
                    f"({', '.join(tactics)}) in workload {pod_name}."
                )
            else:
                title = f"Security Violation Burst: {ev_list[0].description or 'Anomalous Behavior'}"
                summary = f"Detected {len(ev_list)} security events matching {', '.join(techniques)} on {pod_name}."

            inc = SecurityIncident(
                cluster=primary_ev.cluster,
                namespace=ns_name,
                pod=pod_name,
                container=primary_ev.container,
                severity=highest_sev,
                confidence=max(e.confidence for e in ev_list),
                title=title,
                summary=summary,
                tactics=tactics,
                techniques=techniques,
                events=ev_list,
                status="OPEN"
            )
            incidents.append(inc)

        return incidents

