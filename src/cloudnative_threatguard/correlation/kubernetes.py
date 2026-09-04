"""
Single-cluster incident correlation for CloudNative ThreatGuard.

Groups sequential security events by workload into high-level attack-chain
incidents. This is the dataclass-based, single-Kubernetes-cluster sibling
of ``correlation.cross_domain``, which correlates across cloud identity and
Kubernetes runtime domains using a separate Pydantic-based event model.
"""

from typing import List, Optional

from cloudnative_threatguard.runtime.events import SecurityEvent, SecurityIncident

_SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def correlate_incidents(
    events: List[SecurityEvent],
    window_seconds: int = 300,
) -> List[SecurityIncident]:
    """
    Groups sequential security events by pod/workload into high-level attack
    chain incidents. Generates unique '#TG-xxxxxx' incident identifiers with
    combined tactics, techniques, and maximum severity.
    """
    if not events:
        return []

    # Group events by workload key: (namespace, pod)
    grouped: dict = {}
    for ev in events:
        key = f"{ev.namespace}/{ev.pod}" if ev.pod else ev.namespace
        grouped.setdefault(key, []).append(ev)

    incidents: List[SecurityIncident] = []
    for key, ev_list in grouped.items():
        if not ev_list:
            continue

        # Sort events by timestamp
        ev_list = sorted(ev_list, key=lambda x: x.timestamp)

        # Determine aggregate severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)
        highest_sev = "LOW"
        for e in ev_list:
            if e.severity in _SEVERITY_ORDER:
                if _SEVERITY_ORDER.index(e.severity) > _SEVERITY_ORDER.index(highest_sev):
                    highest_sev = e.severity

        # Collect unique tactics and techniques preserving order
        tactics: List[str] = []
        techniques: List[str] = []
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
            status="OPEN",
        )
        incidents.append(inc)

    return incidents
