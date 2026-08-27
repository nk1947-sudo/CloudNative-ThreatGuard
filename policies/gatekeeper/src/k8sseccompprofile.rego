package k8sseccompprofile

default_allowed := ["RuntimeDefault", "Localhost"]

find_containers[c] {
    c := input.review.object.spec.containers[_]
}
find_containers[c] {
    c := input.review.object.spec.initContainers[_]
}
find_containers[c] {
    c := input.review.object.spec.ephemeralContainers[_]
}

get_allowed_profiles = profiles {
    configured := object.get(input.parameters, "allowedProfiles", [])
    count(configured) > 0
    profiles := configured
} else = profiles {
    profiles := default_allowed
}

is_valid_type(type, allowed) {
    allowed[_] == type
}

has_container_seccomp(container, allowed) {
    type := container.securityContext.seccompProfile.type
    is_valid_type(type, allowed)
}

has_pod_seccomp(pod, allowed) {
    type := pod.spec.securityContext.seccompProfile.type
    is_valid_type(type, allowed)
}

is_seccomp_compliant(container, pod, allowed) {
    has_container_seccomp(container, allowed)
}

is_seccomp_compliant(container, pod, allowed) {
    not container.securityContext.seccompProfile
    has_pod_seccomp(pod, allowed)
}

violation[{"msg": msg}] {
    container := find_containers[_]
    allowed := get_allowed_profiles
    not is_seccomp_compliant(container, input.review.object, allowed)
    msg := sprintf("Container '%v' in pod '%v' violates policy [SEC-ADM-007]: seccompProfile.type must be configured to 'RuntimeDefault' (or 'Localhost') to restrict unauthorized kernel system calls.", [container.name, input.review.object.metadata.name])
}
