#!/usr/bin/env python3
"""
CloudNative ThreatGuard — Protected Sample Microservice
A hardened production microservice demonstrating zero-trust container security controls.
"""

from flask import Flask, jsonify, request
import os
import sys
import time

app = Flask(__name__)
START_TIME = time.time()

@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "service": "cloudnative-threatguard-workload",
        "status": "active",
        "security_tier": "hardened",
        "enforced_controls": [
            "runAsNonRoot: true",
            "allowPrivilegeEscalation: false",
            "capabilities.drop: ALL",
            "seccompProfile: RuntimeDefault",
            "readOnlyRootFilesystem: true"
        ]
    }), 200

@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "healthy", "uptime_seconds": round(time.time() - START_TIME, 2)}), 200

@app.route("/readyz", methods=["GET"])
def readyz():
    return jsonify({"status": "ready"}), 200

@app.route("/api/v1/telemetry", methods=["GET"])
def telemetry():
    return jsonify({
        "node": os.environ.get("NODE_NAME", "k8s-node"),
        "pod": os.environ.get("POD_NAME", "threatguard-pod"),
        "namespace": os.environ.get("POD_NAMESPACE", "threatguard"),
        "uid": os.getuid() if hasattr(os, "getuid") else "n/a",
        "gid": os.getgid() if hasattr(os, "getgid") else "n/a",
        "cwd": os.getcwd()
    }), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
