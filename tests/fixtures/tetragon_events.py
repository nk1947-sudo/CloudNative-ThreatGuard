"""
Shared sample raw Tetragon event payloads, reused across detection/correlation
tests instead of every test file hand-building the same JSON shapes.
"""

from typing import Any


def process_exec_event(binary: str, arguments: str = "", namespace: str = "threatguard",
                        pod: str = "sample-app-6c9f", container: str = "web",
                        pid: int = 4100, uid: int = 10001, time: str = "2026-09-05T12:00:00Z") -> dict[str, Any]:
    """A raw Tetragon process_exec event, as seen by DetectionEngine._handle_process_exec."""
    return {
        "time": time,
        "process_exec": {
            "process": {
                "binary": binary,
                "arguments": arguments,
                "pid": pid,
                "uid": uid,
                "pod": {
                    "namespace": namespace,
                    "name": pod,
                    "container": {"name": container},
                },
            }
        },
    }


def sensitive_file_open_event(path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token",
                               binary: str = "/bin/cat", namespace: str = "threatguard",
                               pod: str = "sample-app-6c9f", container: str = "web",
                               time: str = "2026-09-05T12:03:00Z") -> dict[str, Any]:
    """A raw Tetragon process_kprobe/security_file_open event."""
    return {
        "time": time,
        "process_kprobe": {
            "function_name": "security_file_open",
            "process": {
                "binary": binary,
                "pod": {
                    "namespace": namespace,
                    "name": pod,
                    "container": {"name": container},
                },
            },
            "args": [{"file_arg": {"path": path}}, {"int_arg": 0}],
        },
    }


def outbound_connect_event(daddr: str = "198.51.100.23", dport: int = 4444,
                            binary: str = "/usr/local/bin/python", namespace: str = "threatguard",
                            pod: str = "sample-app-6c9f", container: str = "web",
                            time: str = "2026-09-05T12:05:00Z") -> dict[str, Any]:
    """A raw Tetragon process_kprobe/sys_enter_connect event."""
    return {
        "time": time,
        "process_kprobe": {
            "function_name": "sys_enter_connect",
            "process": {
                "binary": binary,
                "pod": {
                    "namespace": namespace,
                    "name": pod,
                    "container": {"name": container},
                },
            },
            "args": [{"int_arg": 3}, {"sock_arg": {"daddr": daddr, "dport": dport, "proto": "TCP"}}],
        },
    }
