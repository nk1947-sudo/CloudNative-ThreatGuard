"""
Privilege Escalation Analyzer for AWS IAM.
Detects well-known AWS IAM privilege escalation vectors (Rhino Security / Bishop Fox taxonomy).
"""


from cloudnative_threatguard.cloudgraphguard.models.findings import FindingType, IAMFinding, PrivilegeEscalationVector
from cloudnative_threatguard.cloudgraphguard.models.iam import IAMPrincipal


class PrivilegeEscalationDetector:
    """
    Evaluates IAM principal policies to identify privilege escalation paths.
    """

    ESCALATION_SIGNATURES = {
        PrivilegeEscalationVector.PASS_ROLE: ["iam:PassRole", "ec2:RunInstances"],
        PrivilegeEscalationVector.ATTACH_USER_POLICY: ["iam:AttachUserPolicy"],
        PrivilegeEscalationVector.ATTACH_ROLE_POLICY: ["iam:AttachRolePolicy"],
        PrivilegeEscalationVector.PUT_USER_POLICY: ["iam:PutUserPolicy"],
        PrivilegeEscalationVector.PUT_ROLE_POLICY: ["iam:PutRolePolicy"],
        PrivilegeEscalationVector.CREATE_POLICY_VERSION: ["iam:CreatePolicyVersion"],
        PrivilegeEscalationVector.SET_DEFAULT_POLICY_VERSION: ["iam:SetDefaultPolicyVersion"],
        PrivilegeEscalationVector.UPDATE_ASSUME_ROLE_POLICY: ["iam:UpdateAssumeRolePolicy"],
        PrivilegeEscalationVector.ASSUME_ROLE: ["sts:AssumeRole"],
    }

    def analyze_principal(self, principal: IAMPrincipal) -> list[IAMFinding]:
        findings: list[IAMFinding] = []
        all_actions = set()

        for policy in principal.attached_policies + principal.inline_policies:
            for stmt in policy.statements:
                if stmt.effect == "Allow":
                    for action in stmt.actions:
                        all_actions.add(action.lower())

        # Check for administrative wildcard
        if "*" in all_actions or "*:*" in all_actions:
            findings.append(
                IAMFinding(
                    finding_type=FindingType.IAM_WILDCARD_PERMISSION,
                    title=f"Full Administrator Access Granted to {principal.name}",
                    description=f"Principal {principal.arn} possesses administrative wildcard permissions (*).",
                    severity="critical",
                    risk_score=95.0,
                    principal_arn=principal.arn,
                    principal_name=principal.name,
                    account_id=principal.account_id,
                    effective_actions=["*"],
                    remediation_suggestion="Scope permissions using least-privilege policy templates.",
                )
            )

        # Check specific escalation vectors
        for vector, sig_actions in self.ESCALATION_SIGNATURES.items():
            matched = all(
                act.lower() in all_actions or "*" in all_actions
                for act in sig_actions
            )
            if matched:
                score = 85.0 if vector != PrivilegeEscalationVector.ASSUME_ROLE else 70.0
                findings.append(
                    IAMFinding(
                        finding_type=FindingType.IAM_PRIVILEGE_ESCALATION,
                        title=f"IAM Privilege Escalation via {vector.value}",
                        description=f"Principal {principal.name} can escalate privileges using vector {vector.value}.",
                        severity="high" if score < 85 else "critical",
                        risk_score=score,
                        principal_arn=principal.arn,
                        principal_name=principal.name,
                        account_id=principal.account_id,
                        escalation_vector=vector,
                        effective_actions=sig_actions,
                        remediation_suggestion=f"Remove or constrain {vector.value} with resource ARN conditions.",
                        evidence={"matched_actions": sig_actions, "vector": vector.value},
                    )
                )

        return findings
