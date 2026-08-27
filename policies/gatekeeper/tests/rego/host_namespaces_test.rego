package k8shostnamespaces

test_hostpid_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-hostpid"},
                "spec": {
                    "hostPID": true,
                    "hostIPC": false,
                    "hostNetwork": false
                }
            }
        },
        "parameters": {}
    }
    violations := violation with input as input
    count(violations) == 1
    contains(violations[_].msg, "hostPID must be false")
}

test_hostipc_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-hostipc"},
                "spec": {
                    "hostPID": false,
                    "hostIPC": true,
                    "hostNetwork": false
                }
            }
        },
        "parameters": {}
    }
    violations := violation with input as input
    count(violations) == 1
    contains(violations[_].msg, "hostIPC must be false")
}

test_hostnetwork_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-hostnetwork"},
                "spec": {
                    "hostPID": false,
                    "hostIPC": false,
                    "hostNetwork": true
                }
            }
        },
        "parameters": {"allowHostNetwork": false}
    }
    violations := violation with input as input
    count(violations) == 1
    contains(violations[_].msg, "hostNetwork must be false")
}

test_isolated_namespaces_allowed {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "secure-pod"},
                "spec": {
                    "hostPID": false,
                    "hostIPC": false,
                    "hostNetwork": false
                }
            }
        },
        "parameters": {"allowHostNetwork": false}
    }
    violations := violation with input as input
    count(violations) == 0
}
