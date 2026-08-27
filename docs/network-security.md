# CloudNative ThreatGuard — Network Security & Micro-segmentation

This document details the network security architecture, traffic isolation boundaries, and least-privilege egress policies implemented by CloudNative ThreatGuard.

---

## 1. Network Security Architecture

In modern zero-trust Kubernetes deployments, workload isolation at the network layer is critical to prevent lateral movement following a container compromise.

```
       [ Cluster Ingress / Test Pod ]
                     |
                     | TCP 8080 (Allowed Ingress)
                     v
       +----------------------------+
       |   threatguard-app (Pod)    |
       +----------------------------+
         |                        |
         | DNS (UDP/TCP 53)       | External Internet / Other Namespaces
         v                        v
+------------------+         [ BLOCKED ]
| kube-system      |         (NetworkPolicy Default Egress Deny)
| CoreDNS Pods     |
+------------------+
```

---

## 2. Policy Enforcement Breakdown

The policy `app/k8s/network-policy.yaml` establishes an explicit default-deny perimeter for the protected application:

### Ingress Filtering
- **Permitted**: Incoming HTTP requests on application port `8080` from within the namespace or authorized gateway pods.
- **Denied**: Direct port access from arbitrary external pods or unauthorized cross-namespace traffic.

### Egress Filtering
- **Permitted**: Standard DNS queries to `kube-system` CoreDNS pods on `UDP` and `TCP` port `53`.
- **Denied**:
  - Direct outbound traffic to the public internet (mitigating C2 beacons, reverse shells, and external data exfiltration).
  - Outbound connections to other namespaces or sensitive cluster internal control planes (mitigating lateral movement to the Kubernetes API server or etcd).

---

## 3. Defense-in-Depth with eBPF

While `NetworkPolicy` operates at the CNI / packet filter level (e.g., Netfilter / Cilium / Calico iptables), **Tetragon eBPF** provides kernel-level observability for the socket syscall itself (`sys_enter_connect` under rule `RUNTIME-006`).

This ensures that even if an attacker attempts an outbound socket connection that is blocked by the NetworkPolicy, security teams still receive high-fidelity detection alerts detailing:
- The exact process name initiating the socket
- The target IP and destination port
- The container PID and parent process context
