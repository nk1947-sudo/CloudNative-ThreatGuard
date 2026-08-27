package k8shostfilesystem

test_docker_socket_mount_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-docker-sock"},
                "spec": {
                    "volumes": [{
                        "name": "dockersock",
                        "hostPath": {"path": "/var/run/docker.sock"}
                    }]
                }
            }
        },
        "parameters": {}
    }
    violations := violation with input as input
    count(violations) == 1
    contains(violations[_].msg, "mounting hostPath '/var/run/docker.sock' is strictly prohibited")
}

test_root_mount_denied {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "insecure-root-mount"},
                "spec": {
                    "volumes": [{
                        "name": "host-root",
                        "hostPath": {"path": "/"}
                    }]
                }
            }
        },
        "parameters": {}
    }
    violations := violation with input as input
    count(violations) == 1
    contains(violations[_].msg, "mounting hostPath '/' is strictly prohibited")
}

test_safe_empty_dir_volume_allowed {
    input := {
        "review": {
            "object": {
                "metadata": {"name": "secure-pod"},
                "spec": {
                    "volumes": [{
                        "name": "tmp-dir",
                        "emptyDir": {}
                    }]
                }
            }
        },
        "parameters": {}
    }
    violations := violation with input as input
    count(violations) == 0
}
