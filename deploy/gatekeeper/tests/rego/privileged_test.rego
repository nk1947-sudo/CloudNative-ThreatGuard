package k8sprivilegedcontainer

test_privileged_container_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-pod"},
                "spec": {
                    "containers": [{
                        "name": "web",
                        "securityContext": {"privileged": true}
                    }]
                }
            }
        },
        "parameters": {"exemptContainers": []}
    }
    violations := violation with input as input
    count(violations) == 1
    contains(violations[_].msg, "privileged mode must be false")
}

test_unprivileged_container_allowed {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "secure-pod"},
                "spec": {
                    "containers": [{
                        "name": "web",
                        "securityContext": {"privileged": false}
                    }]
                }
            }
        },
        "parameters": {"exemptContainers": []}
    }
    violations := violation with input as input
    count(violations) == 0
}

test_privileged_container_exempted {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "system-agent"},
                "spec": {
                    "containers": [{
                        "name": "node-agent",
                        "securityContext": {"privileged": true}
                    }]
                }
            }
        },
        "parameters": {"exemptContainers": ["node-agent"]}
    }
    violations := violation with input as input
    count(violations) == 0
}
