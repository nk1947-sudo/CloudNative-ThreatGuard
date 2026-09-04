"""
Transparent and Explainable Security Risk Scoring Engine for CloudNative ThreatGuard.
Evaluates workload privilege, asset criticality, MITRE tactics, event volume,
and temporal clustering to produce a bounded 0-100 risk score with full attribution.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from enum import Enum

from cloudnative_threatguard.runtime.events import SecurityEvent


class RiskTier(str, Enum):
    LOW = "LOW"            # 0 - 39
    MEDIUM = "MEDIUM"      # 40 - 69
    HIGH = "HIGH"          # 70 - 89
    CRITICAL = "CRITICAL"  # 90 - 100


@dataclass
class RiskContributor:
    factor_name: str
    impact_points: float
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RiskAssessment:
    composite_risk_score: float
    risk_tier: str
    workload_ref: str
    top_risk_contributors: List[RiskContributor] = field(default_factory=list)
    factor_breakdown: Dict[str, float] = field(default_factory=dict)
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "composite_risk_score": round(self.composite_risk_score, 1),
            "risk_tier": self.risk_tier,
            "workload_ref": self.workload_ref,
            "top_risk_contributors": [c.to_dict() for c in self.top_risk_contributors],
            "factor_breakdown": {k: round(v, 1) for k, v in self.factor_breakdown.items()},
            "evaluated_at": self.evaluated_at
        }


class RiskScoringEngine:
    """
    Computes explainable risk scores combining behavioral telemetry,
    Kubernetes workload configuration context, and MITRE technique weighting.
    """

    # Asset Criticality Weightings
    NAMESPACE_WEIGHTS = {
        "kube-system": 30.0,
        "threatguard": 20.0,
        "threatguard-lab": 10.0,
        "default": 10.0
    }

    # MITRE Technique Base Weights
    TECHNIQUE_WEIGHTS = {
        "T1611": 25.0,     # Escape to Host
        "T1068": 20.0,     # Exploitation for Privilege Escalation
        "T1552.007": 22.0, # Unsecured Credentials: SA Token
        "T1003": 20.0,     # OS Credential Dumping
        "T1059.004": 18.0, # Unix Shell
        "T1071": 15.0,     # Outbound C2
        "T1071.001": 15.0,
        "T1105": 14.0,     # Ingress Tool Transfer
        "T1610": 16.0,     # Deploy Container / Admission Bypass
        "T1082": 10.0,     # System Information Discovery
        "T1496": 22.0,     # Resource Hijacking (cryptomining)
    }

    def evaluate_workload(
        self,
        events: List[SecurityEvent],
        workload_ref: str = "threatguard/target-pod",
        workload_spec: Optional[Dict[str, Any]] = None
    ) -> RiskAssessment:
        """
        Calculates composite risk score for a workload given its events and optional pod spec.
        """
        contributors: List[RiskContributor] = []
        breakdown: Dict[str, float] = {
            "severity_points": 0.0,
            "asset_criticality": 0.0,
            "privilege_level": 0.0,
            "network_exposure": 0.0,
            "event_volume_clustering": 0.0,
            "mitre_technique_weight": 0.0
        }

        if not events and not workload_spec:
            return RiskAssessment(
                composite_risk_score=0.0,
                risk_tier=RiskTier.LOW.value,
                workload_ref=workload_ref,
                top_risk_contributors=[],
                factor_breakdown=breakdown
            )

        # 1. Base Severity Points (max of events + accumulation of high/criticals)
        max_severity_score = 0.0
        for ev in events:
            sev = ev.severity.upper()
            if sev == "CRITICAL":
                max_severity_score = max(max_severity_score, 40.0)
            elif sev == "HIGH":
                max_severity_score = max(max_severity_score, 25.0)
            elif sev == "MEDIUM":
                max_severity_score = max(max_severity_score, 15.0)
            elif sev == "LOW":
                max_severity_score = max(max_severity_score, 5.0)

        # Event volume accumulation (diminishing returns)
        volume_points = min(len(events) * 4.0, 16.0)
        breakdown["severity_points"] = max_severity_score + volume_points
        if breakdown["severity_points"] > 0:
            contributors.append(RiskContributor(
                factor_name="Behavioral Severity",
                impact_points=breakdown["severity_points"],
                description=f"Accumulated from {len(events)} security events with max severity"
            ))

        # 2. Asset Criticality (Namespace Sensitivity)
        namespace = workload_ref.split("/")[0] if "/" in workload_ref else "threatguard"
        ns_pts = self.NAMESPACE_WEIGHTS.get(namespace, 10.0)
        breakdown["asset_criticality"] = ns_pts
        contributors.append(RiskContributor(
            factor_name="Asset Criticality",
            impact_points=ns_pts,
            description=f"Namespace '{namespace}' asset sensitivity weighting"
        ))

        # 3. Workload Privilege Level
        priv_pts = 0.0
        if workload_spec:
            # Check privileged flag
            if workload_spec.get("privileged", False):
                priv_pts += 25.0
                contributors.append(RiskContributor(
                    factor_name="Privileged Container",
                    impact_points=25.0,
                    description="Workload is configured with privileged: true container execution"
                ))
            # Check host namespaces
            if workload_spec.get("hostPID") or workload_spec.get("hostNetwork") or workload_spec.get("hostIPC"):
                priv_pts += 20.0
                contributors.append(RiskContributor(
                    factor_name="Host Namespaces",
                    impact_points=20.0,
                    description="Workload shares host Linux namespaces (PID, IPC, or Network)"
                ))
            # Check root user
            if workload_spec.get("runAsUser") == 0 or workload_spec.get("runAsNonRoot") is False:
                priv_pts += 15.0
                contributors.append(RiskContributor(
                    factor_name="Root User Execution",
                    impact_points=15.0,
                    description="Container runs with root UID (0)"
                ))
            # Check writable rootfs
            if workload_spec.get("readOnlyRootFilesystem") is False:
                priv_pts += 10.0
                contributors.append(RiskContributor(
                    factor_name="Writable Root Filesystem",
                    impact_points=10.0,
                    description="Container root filesystem is writable"
                ))

        breakdown["privilege_level"] = priv_pts

        # 4. Network Exposure
        net_pts = 0.0
        for ev in events:
            if ev.action in ["net_connect", "socket_connect", "outbound_egress_attempt"] or "curl" in ev.process or "wget" in ev.process:
                net_pts = max(net_pts, 20.0)
                contributors.append(RiskContributor(
                    factor_name="Outbound Network Activity",
                    impact_points=20.0,
                    description=f"Workload initiated external network traffic via {ev.process}"
                ))
                break
        breakdown["network_exposure"] = net_pts

        # 5. MITRE Technique Risk Weighting
        mitre_pts = 0.0
        observed_techniques = set()
        for ev in events:
            tech = ev.mitre_technique
            if tech and tech not in observed_techniques:
                observed_techniques.add(tech)
                pts = self.TECHNIQUE_WEIGHTS.get(tech, 10.0)
                mitre_pts += pts

        # Cap MITRE technique contribution at 35.0
        capped_mitre_pts = min(mitre_pts, 35.0)
        breakdown["mitre_technique_weight"] = capped_mitre_pts
        if capped_mitre_pts > 0:
            contributors.append(RiskContributor(
                factor_name="MITRE ATT&CK Alignment",
                impact_points=capped_mitre_pts,
                description=f"Matched {len(observed_techniques)} techniques: {', '.join(sorted(observed_techniques))}"
            ))

        # 6. Temporal Clustering (Burst Detection)
        if len(events) >= 2:
            try:
                t0 = datetime.fromisoformat(events[0].timestamp.replace("Z", "+00:00"))
                t1 = datetime.fromisoformat(events[-1].timestamp.replace("Z", "+00:00"))
                delta_sec = abs((t1 - t0).total_seconds())
                if delta_sec < 120:  # Rapid burst within 2 minutes
                    burst_pts = 12.0
                    breakdown["event_volume_clustering"] = burst_pts
                    contributors.append(RiskContributor(
                        factor_name="Temporal Clustering",
                        impact_points=burst_pts,
                        description=f"{len(events)} events occurred within {int(delta_sec)} seconds (rapid attack burst)"
                    ))
            except Exception:
                pass

        # Calculate composite score (sum with normalization scale bounded at 100.0)
        raw_total = sum(breakdown.values())
        composite_score = min(100.0, raw_total * 0.75)  # Calibration factor

        # Assign risk tier
        if composite_score >= 85.0:
            tier = RiskTier.CRITICAL.value
        elif composite_score >= 65.0:
            tier = RiskTier.HIGH.value
        elif composite_score >= 35.0:
            tier = RiskTier.MEDIUM.value
        else:
            tier = RiskTier.LOW.value

        # Sort contributors by impact descending
        contributors.sort(key=lambda c: c.impact_points, reverse=True)

        return RiskAssessment(
            composite_risk_score=composite_score,
            risk_tier=tier,
            workload_ref=workload_ref,
            top_risk_contributors=contributors[:5],
            factor_breakdown=breakdown
        )
