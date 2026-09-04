"""
Unified Cross-Domain Risk Scoring Engine.
Calculates composite risk scores by combining Cloud IAM attack surface,
workload vulnerabilities, runtime threat detections, and resource sensitivity.
Does not replace individual domain engines; aggregates them into a transparent factor model.
"""

from typing import List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from cloudnative_threatguard.correlation.cross_domain.models.event import Severity
from .correlation_engine import CorrelatedCluster


class RiskFactor(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    source: str  # "cloudgraphguard", "threatguard", "context"
    factor: str
    contribution: float = Field(ge=0.0, le=100.0)
    description: str


class UnifiedRiskAssessment(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    overall_score: float = Field(ge=0.0, le=100.0)
    severity: Severity
    iam_subtotal: float
    runtime_subtotal: float
    factors: List[RiskFactor] = Field(default_factory=list)
    remediation_urgency: str
    calculation_formula: str

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class CrossDomainRiskEvaluator:
    """
    Evaluates multi-factor risk across Cloud IAM and Kubernetes runtime domains.

    Formula:
    Score = min(100.0, IAM_Factor + Runtime_Factor + Resource_Sensitivity + KillChain_Amplifier)
    """

    @classmethod
    def evaluate_cluster(cls, cluster: CorrelatedCluster) -> UnifiedRiskAssessment:
        factors: List[RiskFactor] = []
        iam_subtotal = 0.0
        runtime_subtotal = 0.0

        # 1. IAM Factors (CloudGraphGuard)
        if cluster.iam_events:
            for ev in cluster.iam_events:
                score = ev.risk_score
                if "Privilege Escalation" in ev.description or (ev.action and "PassRole" in ev.action):
                    contribution = min(35.0, score * 0.4)
                    factors.append(
                        RiskFactor(
                            source="cloudgraphguard",
                            factor="iam_privilege_escalation",
                            contribution=round(contribution, 1),
                            description="Cloud IAM principal possesses privilege escalation path (e.g. PassRole)",
                        )
                    )
                    iam_subtotal += contribution
                    break
                elif "Wildcard" in ev.description or (ev.action and "*" in ev.action):
                    contribution = min(30.0, score * 0.35)
                    factors.append(
                        RiskFactor(
                            source="cloudgraphguard",
                            factor="iam_wildcard_permission",
                            contribution=round(contribution, 1),
                            description="Cloud IAM principal has administrative wildcard permissions (*)",
                        )
                    )
                    iam_subtotal += contribution
                    break
            if not factors:
                contribution = min(25.0, cluster.iam_events[0].risk_score * 0.3)
                factors.append(
                    RiskFactor(
                        source="cloudgraphguard",
                        factor="iam_excessive_permission",
                        contribution=round(contribution, 1),
                        description="Cloud IAM principal possesses elevated cloud access",
                    )
                )
                iam_subtotal += contribution

        # 2. Runtime & Admission Factors (ThreatGuard)
        has_credential_access = False
        has_shell_exec = False
        has_egress = False

        for ev in cluster.runtime_events:
            rule = ev.detection_rule or ""
            desc = ev.description.lower()
            if "004" in rule or "token" in desc or "secret" in desc:
                has_credential_access = True
            elif "001" in rule or "shell" in desc or "bash" in desc or "sh" in desc:
                has_shell_exec = True
            elif "006" in rule or "outbound" in desc or "connect" in desc:
                has_egress = True

        if has_credential_access:
            contribution = 40.0
            factors.append(
                RiskFactor(
                    source="threatguard",
                    factor="credential_access",
                    contribution=contribution,
                    description="ServiceAccount token or sensitive credentials accessed by unauthorized process",
                )
            )
            runtime_subtotal += contribution

        if has_shell_exec:
            contribution = 25.0
            factors.append(
                RiskFactor(
                    source="threatguard",
                    factor="runtime_shell_execution",
                    contribution=contribution,
                    description="Interactive shell spawned inside container (MITRE T1059.004)",
                )
            )
            runtime_subtotal += contribution

        if has_egress:
            contribution = 15.0
            factors.append(
                RiskFactor(
                    source="threatguard",
                    factor="external_network_egress",
                    contribution=contribution,
                    description="Outbound network socket opened to external IP (potential exfiltration)",
                )
            )
            runtime_subtotal += contribution

        # Admission violation contribution
        if cluster.admission_events:
            contribution = 10.0
            factors.append(
                RiskFactor(
                    source="threatguard",
                    factor="admission_policy_violation",
                    contribution=contribution,
                    description="Workload violates pod security standards (OPA Gatekeeper constraint)",
                )
            )
            runtime_subtotal += contribution

        # 3. Cross-domain kill chain amplifier
        is_cross_domain = bool(cluster.iam_events and (cluster.runtime_events or cluster.admission_events))
        amplifier = 0.0
        if is_cross_domain and len(factors) >= 2:
            amplifier = 10.0
            factors.append(
                RiskFactor(
                    source="context",
                    factor="cross_domain_kill_chain_correlation",
                    contribution=amplifier,
                    description="Active multi-stage progression from cloud identity to running container exploit",
                )
            )

        total_score = min(100.0, round(iam_subtotal + runtime_subtotal + amplifier, 1))

        if total_score >= 85.0:
            sev = Severity.CRITICAL
            urgency = "P1-Immediate"
        elif total_score >= 65.0:
            sev = Severity.HIGH
            urgency = "P2-Urgent"
        elif total_score >= 40.0:
            sev = Severity.MEDIUM
            urgency = "P3-Standard"
        else:
            sev = Severity.LOW
            urgency = "P4-Low"

        formula = "overall_score = min(100.0, sum(IAM_Factors) + sum(Runtime_Factors) + KillChain_Amplifier)"

        return UnifiedRiskAssessment(
            overall_score=total_score,
            severity=sev,
            iam_subtotal=round(iam_subtotal, 1),
            runtime_subtotal=round(runtime_subtotal, 1),
            factors=factors,
            remediation_urgency=urgency,
            calculation_formula=formula,
        )
