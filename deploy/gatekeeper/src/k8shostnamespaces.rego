package k8shostnamespaces

pod = input.review.object

violation[{"msg": msg}] {
    pod.spec.hostPID == true
    msg := sprintf("Pod '%v' violates policy [SEC-ADM-002]: hostPID must be false to prevent cross-container process inspection and kernel manipulation.", [pod.metadata.name])
}

violation[{"msg": msg}] {
    pod.spec.hostIPC == true
    msg := sprintf("Pod '%v' violates policy [SEC-ADM-002]: hostIPC must be false to prevent unauthorized inter-process memory sharing with the host.", [pod.metadata.name])
}

violation[{"msg": msg}] {
    allow_net := object.get(input.parameters, "allowHostNetwork", false)
    allow_net == false
    pod.spec.hostNetwork == true
    msg := sprintf("Pod '%v' violates policy [SEC-ADM-002]: hostNetwork must be false to prevent sniffing host network interfaces and bypassing NetworkPolicies.", [pod.metadata.name])
}
