package k8snonrootuser

test_missing_non_root_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-root-pod"},
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
    contains(violations[_].msg, "runAsNonRoot must be true")
}

test_explicit_root_uid_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-root-uid"},
                "spec": {
                    "securityContext": {"runAsUser": 0},
                    "containers": [{
                        "name": "web",
                        "securityContext": {"runAsNonRoot": true}
                    }]
                }
            }
        },
        "parameters": {}
    }
    violations := violation with input as input
    count(violations) == 1
}

test_pod_level_non_root_allowed {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "secure-pod"},
                "spec": {
                    "securityContext": {
                        "runAsNonRoot": true,
                        "runAsUser": 10001
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

test_container_level_non_root_allowed {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "secure-pod"},
                "spec": {
                    "containers": [{
                        "name": "web",
                        "securityContext": {
                            "runAsNonRoot": true,
                            "runAsUser": 10001
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
