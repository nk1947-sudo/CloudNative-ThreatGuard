"""
Detection Engine for CloudNative ThreatGuard.
Parses raw Tetragon eBPF telemetry, evaluates security detection rules,
enriches with MITRE ATT&CK metadata, and emits structured detections.

Incident-level grouping of these detections lives in
``cloudnative_threatguard.correlation.kubernetes`` -- this module is
scoped to turning one raw event into zero or one ``ThreatGuardDetection``.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any

from cloudnative_threatguard.runtime.events import ThreatGuardDetection
from cloudnative_threatguard.utils.io import read_text_lines_multi_encoding

from .rules import DETECTION_RULES


class DetectionEngine:
    def __init__(self, protected_namespace: str = "threatguard"):
        self.protected_namespace = protected_namespace
        self.rules = DETECTION_RULES
        self.detections: list[ThreatGuardDetection] = []
        self.total_events_processed: int = 0

    def process_raw_tetragon_event(self, raw_event: dict[str, Any], record: bool = True) -> ThreatGuardDetection | None:
        """
        Evaluates a single raw Tetragon event against detection rules.
        """
        self.total_events_processed += 1
        det = self._evaluate_raw_event(raw_event)
        if det and record:
            self.detections.append(det)
        return det

    def process_event(self, raw_event: dict[str, Any], record: bool = True) -> ThreatGuardDetection | None:
        """Convenience alias for process_raw_tetragon_event."""
        return self.process_raw_tetragon_event(raw_event, record=record)

    def _evaluate_raw_event(self, raw_event: dict[str, Any]) -> ThreatGuardDetection | None:

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

    def _handle_process_exec(self, exec_event: dict[str, Any], event_time: str) -> ThreatGuardDetection | None:
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
                action="process_exec",
                event_type=rule["event_type"],
                severity=rule["severity"],
                detection_name=rule["detection_name"],
                rule_id=rule["rule_id"],
                technique=rule["technique"],
                tactic=rule["tactic"],
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
                action="process_exec",
                event_type=rule["event_type"],
                severity=rule["severity"],
                detection_name=rule["detection_name"],
                rule_id=rule["rule_id"],
                technique=rule["technique"],
                tactic=rule["tactic"],
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
                action="process_exec",
                event_type=rule["event_type"],
                severity=rule["severity"],
                detection_name=rule["detection_name"],
                rule_id=rule["rule_id"],
                technique=rule["technique"],
                tactic=rule["tactic"],
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
                action="priv_escalation",
                event_type=rule["event_type"],
                severity=rule["severity"],
                detection_name=rule["detection_name"],
                rule_id=rule["rule_id"],
                technique=rule["technique"],
                tactic=rule["tactic"],
                technique_name=rule["technique_name"],
                evidence={
                    "binary": binary,
                    "arguments": args,
                    "pid": proc.get("pid"),
                    "cap_effective": proc.get("cap", {}).get("effective", [])
                }
            )

        # RUNTIME-007: Cryptomining process execution
        if basename in ["xmrig", "minerd", "ccminer", "cpuminer", "cgminer", "ethminer"]:
            rule = self.rules["RUNTIME-007"]
            return ThreatGuardDetection(
                timestamp=event_time,
                namespace=namespace or self.protected_namespace,
                pod=pod_name,
                container=container,
                process=binary,
                command=f"{binary} {args}".strip(),
                action="process_exec",
                event_type=rule["event_type"],
                severity=rule["severity"],
                detection_name=rule["detection_name"],
                rule_id=rule["rule_id"],
                technique=rule["technique"],
                tactic=rule["tactic"],
                technique_name=rule["technique_name"],
                evidence={
                    "binary": binary,
                    "arguments": args,
                    "pid": proc.get("pid")
                }
            )

        return None

    def _handle_kprobe(self, kprobe_event: dict[str, Any], event_time: str) -> ThreatGuardDetection | None:
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
                        action="file_read",
                        event_type=rule["event_type"],
                        severity=rule["severity"],
                        detection_name=rule["detection_name"],
                        rule_id=rule["rule_id"],
                        technique=rule["technique"],
                        tactic=rule["tactic"],
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
                action="net_connect",
                event_type=rule["event_type"],
                severity=rule["severity"],
                detection_name=rule["detection_name"],
                rule_id=rule["rule_id"],
                technique=rule["technique"],
                tactic=rule["tactic"],
                technique_name=rule["technique_name"],
                evidence={
                    "destination_ip": sock_info.get("daddr", ""),
                    "destination_port": sock_info.get("dport", ""),
                    "protocol": sock_info.get("proto", "TCP"),
                    "process": proc.get("binary", "")
                }
            )

        return None

    def _handle_generic_event(self, event: dict[str, Any], event_time: str) -> ThreatGuardDetection | None:
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
                action=event.get("action", "detected"),
                event_type=rule["event_type"],
                severity=rule["severity"],
                detection_name=rule["detection_name"],
                rule_id=rule["rule_id"],
                technique=rule["technique"],
                tactic=rule["tactic"],
                technique_name=rule["technique_name"],
                evidence=event.get("evidence", {})
            )
        return None

    def ingest_file(self, filepath: str) -> list[ThreatGuardDetection]:
        """
        Parses a file containing line-delimited JSON events.
        """
        new_detections = []
        if not os.path.exists(filepath):
            return new_detections

        for line in read_text_lines_multi_encoding(filepath):
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

    def get_summary(self) -> dict[str, Any]:
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
