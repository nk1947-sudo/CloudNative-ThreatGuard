package k8sprivilegedcontainer

find_containers[c] {
    c := input.review.object.spec.containers[_]
}
find_containers[c] {
    c := input.review.object.spec.initContainers[_]
}
find_containers[c] {
    c := input.review.object.spec.ephemeralContainers[_]
}

is_exempt(container, exempt_list) {
    exempt_list[_] == container.name
}

violation[{"msg": msg}] {
    container := find_containers[_]
    not is_exempt(container, object.get(input.parameters, "exemptContainers", []))
    container.securityContext.privileged == true
    msg := sprintf("Container '%v' in pod '%v' violates policy [SEC-ADM-001]: privileged mode must be false to prevent full container breakout.", [container.name, input.review.object.metadata.name])
}
