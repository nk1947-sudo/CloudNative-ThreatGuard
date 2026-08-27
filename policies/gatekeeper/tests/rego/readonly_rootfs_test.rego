package k8sreadonlyrootfs

test_writable_rootfs_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-writable-root"},
                "spec": {
                    "containers": [{
                        "name": "web",
                        "securityContext": {"readOnlyRootFilesystem": false}
                    }]
                }
            }
        },
        "parameters": {"exemptContainers": []}
    }
    violations := violation with input as input
    count(violations) == 1
    contains(violations[_].msg, "readOnlyRootFilesystem must be true")
}

test_missing_readonly_rootfs_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-default-root"},
                "spec": {
                    "containers": [{
                        "name": "web",
                        "securityContext": {}
                    }]
                }
            }
        },
        "parameters": {"exemptContainers": []}
    }
    violations := violation with input as input
    count(violations) == 1
}

test_readonly_rootfs_allowed {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "secure-pod"},
                "spec": {
                    "containers": [{
                        "name": "web",
                        "securityContext": {"readOnlyRootFilesystem": true}
                    }]
                }
            }
        },
        "parameters": {"exemptContainers": []}
    }
    violations := violation with input as input
    count(violations) == 0
}
