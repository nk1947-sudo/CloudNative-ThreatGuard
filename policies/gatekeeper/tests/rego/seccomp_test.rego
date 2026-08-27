package k8sseccompprofile

test_missing_seccomp_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-no-seccomp"},
                "spec": {
                    "containers": [{
                        "name": "web",
                        "securityContext": {}
                    }]
                }
            }
        },
        "parameters": {}
    }
    violations := violation with input as input
    count(violations) == 1
    contains(violations[_].msg, "seccompProfile.type must be configured to 'RuntimeDefault'")
}

test_unconfined_seccomp_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-unconfined-seccomp"},
                "spec": {
                    "containers": [{
                        "name": "web",
                        "securityContext": {
                            "seccompProfile": {"type": "Unconfined"}
                        }
                    }]
                }
            }
        },
        "parameters": {}
    }
    violations := violation with input as input
    count(violations) == 1
}

test_runtimedefault_container_seccomp_allowed {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "secure-pod"},
                "spec": {
                    "containers": [{
                        "name": "web",
                        "securityContext": {
                            "seccompProfile": {"type": "RuntimeDefault"}
                        }
                    }]
                }
            }
        },
        "parameters": {}
    }
    violations := violation with input as input
    count(violations) == 0
}

test_runtimedefault_pod_seccomp_allowed {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "secure-pod"},
                "spec": {
                    "securityContext": {
                        "seccompProfile": {"type": "RuntimeDefault"}
                    },
                    "containers": [{
                        "name": "web",
                        "securityContext": {}
                    }]
                }
            }
        },
        "parameters": {}
    }
    violations := violation with input as input
    count(violations) == 0
}
