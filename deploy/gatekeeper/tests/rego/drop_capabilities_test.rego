package k8sdropcapabilities

test_missing_drop_all_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-no-drop"},
                "spec": {
                    "containers": [{
                        "name": "web",
                        "securityContext": {
                            "capabilities": {"drop": ["NET_RAW"]}
                        }
                    }]
                }
            }
        },
        "parameters": {}
    }
    violations := violation with input as input
    count(violations) == 1
    contains(violations[_].msg, "capabilities.drop must explicitly include 'ALL'")
}

test_adding_dangerous_sys_admin_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-cap-sys-admin"},
                "spec": {
                    "containers": [{
                        "name": "web",
                        "securityContext": {
                            "capabilities": {
                                "drop": ["ALL"],
                                "add": ["SYS_ADMIN"]
                            }
                        }
                    }]
                }
            }
        },
        "parameters": {}
    }
    violations := violation with input as input
    count(violations) == 1
    contains(violations[_].msg, "added capability 'SYS_ADMIN' is prohibited")
}

test_drop_all_only_allowed {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "secure-pod"},
                "spec": {
                    "containers": [{
                        "name": "web",
                        "securityContext": {
                            "capabilities": {
                                "drop": ["ALL"]
                            }
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
