"""
CloudGraphGuard Event Adapter.
Converts IAM findings and attack path detections into normalized UnifiedSecurityEvents.
"""

from typing import Any

from cloudnative_threatguard.cloudgraphguard.models.findings import IAMFinding
from cloudnative_threatguard.correlation.cross_domain.models.event import (
    CloudProvider,
    EventSource,
    EventType,
    Severity,
    UnifiedSecurityEvent,
)


class CloudGraphGuardAdapter:
    """
    Translates CloudGraphGuard IAM findings into the platform-wide normalized event format.
    """

    @classmethod
    def to_unified_event(cls, finding: IAMFinding | dict[str, Any]) -> UnifiedSecurityEvent:
        if isinstance(finding, dict):
            finding_obj = IAMFinding(**finding)
        else:
            finding_obj = finding

        # Map severity
        sev_str = str(finding_obj.severity).lower()
        if sev_str in ["critical", "crit"]:
            sev = Severity.CRITICAL
        elif sev_str in ["high"]:
            sev = Severity.HIGH
        elif sev_str in ["medium", "med"]:
            sev = Severity.MEDIUM
        else:
            sev = Severity.LOW

        # Extract primary action from escalation vector or effective actions
        action = None
        if finding_obj.escalation_vector:
            action = finding_obj.escalation_vector.value
        elif finding_obj.effective_actions:
            action = finding_obj.effective_actions[0]

        evidence = dict(finding_obj.evidence)
        if finding_obj.attack_path:
            evidence["attack_path"] = finding_obj.attack_path
        if finding_obj.remediation_suggestion:
            evidence["remediation_suggestion"] = finding_obj.remediation_suggestion
        if finding_obj.effective_actions:
            evidence["effective_actions"] = finding_obj.effective_actions

        return UnifiedSecurityEvent(
            source=EventSource.CLOUDGRAPHGUARD,
            event_type=EventType.IAM_RISK,
            provider=CloudProvider.AWS,
            account_id=finding_obj.account_id,
            principal_id=finding_obj.principal_name,
            principal_arn=finding_obj.principal_arn,
            role_arn=finding_obj.target_role_arn,
            resource_arn=finding_obj.target_resource_arn,
            action=action,
            severity=sev,
            risk_score=float(finding_obj.risk_score),
            confidence=0.95,
            detection_rule=finding_obj.finding_type.value if hasattr(finding_obj.finding_type, "value") else str(finding_obj.finding_type),
            description=finding_obj.description,
            evidence=evidence,
            metadata={
                "original_finding_id": finding_obj.finding_id,
                "engine": "cloudgraphguard",
            },
        )

    @classmethod
    def batch_to_unified_events(cls, findings: list[IAMFinding | dict[str, Any]]) -> list[UnifiedSecurityEvent]:
        return [cls.to_unified_event(f) for f in findings]
