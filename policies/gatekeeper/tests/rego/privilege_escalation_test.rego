package k8sprivilegeescalation

test_allow_privilege_escalation_true_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-priv-esc"},
                "spec": {
                    "containers": [{
                        "name": "web",
                        "securityContext": {"allowPrivilegeEscalation": true}
                    }]
                }
            }
        },
        "parameters": {}
    }
    violations := violation with input as input
    count(violations) == 1
    contains(violations[_].msg, "allowPrivilegeEscalation must be false")
}

test_missing_allow_privilege_escalation_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-default-priv-esc"},
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
    contains(violations[_].msg, "allowPrivilegeEscalation must be false")
}

test_allow_privilege_escalation_false_allowed {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "secure-pod"},
                "spec": {
                    "containers": [{
                        "name": "web",
                        "securityContext": {"allowPrivilegeEscalation": false}
                    }]
                }
            }
        },
        "parameters": {}
    }
    violations := violation with input as input
    count(violations) == 0
}
