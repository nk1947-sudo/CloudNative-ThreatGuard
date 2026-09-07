# Live Kubernetes Ownership Resolution: RBAC & Operating Modes

`threatguard remediate` needs to know which Deployment/StatefulSet/DaemonSet
actually owns a compromised Pod before it can safely generate a targeted
remediation command (a Pod name is never that controller's name). This
document covers the three ways that resolution can happen, and the exact
permissions the optional live-lookup mode requires.

## Operating modes

| Mode | Trigger | Requires a cluster? |
|---|---|---|
| **Offline (default)** | No flag | No. Uses `ownerReferences` already attached to the event, or a naming-pattern heuristic on the Pod name. |
| **Live lookup** | `threatguard remediate <id> --live-k8s` | Yes, a working `kubeconfig` with the RBAC below. |
| **Fallback within live mode** | Automatic, when the live lookup fails for any reason | No -- silently degrades to the same offline behavior. |

No other ThreatGuard command (`status`, `incidents`, `workloads`, `simulate`,
`report`, `admission validate`, `verify`, `demo`) requires a kubeconfig at
all, and `remediate` itself does not require one unless `--live-k8s` is
passed. This project's existing `status`/`report evidence` commands already
make optional, best-effort `kubectl` calls in the same spirit -- `--live-k8s`
follows that established pattern rather than introducing a new one.

## Minimum required RBAC

The live lookup issues exactly one or two read-only calls per remediation
(`kubectl get pod ... -o json`, and, when the Pod is owned by a ReplicaSet,
`kubectl get replicaset ... -o json` to resolve the owning Deployment
authoritatively instead of guessing from its name). It never lists, watches,
creates, updates, deletes, or patches anything.

Grant a dedicated ServiceAccount exactly this, scoped to the namespace(s)
being investigated -- never cluster-admin, and never write access:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: threatguard-ownership-reader
  namespace: threatguard
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get"]
  - apiGroups: ["apps"]
    resources: ["replicasets"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: threatguard-ownership-reader-binding
  namespace: threatguard
subjects:
  - kind: ServiceAccount
    name: threatguard-operator
    namespace: threatguard
roleRef:
  kind: Role
  name: threatguard-ownership-reader
  apiGroup: rbac.authorization.k8s.io
```

If incidents span multiple namespaces, bind the same `Role` in each
namespace individually rather than switching to a `ClusterRole` -- least
privilege applies per-namespace here since ownership lookups never need to
cross namespace boundaries.

## Fallback behavior and its limits

Every one of the following is treated identically by the resolver -- as an
unavailable lookup, never as "no owner" -- and results in a safe fallback to
the offline naming-pattern heuristic (or, if that also can't confidently
resolve an owner, a manual-remediation recommendation instead of a guessed
command):

- `kubectl` is not installed or not on `PATH`.
- No kubeconfig / cluster unreachable.
- The RBAC above has not been granted (`Forbidden`).
- The Pod (or its ReplicaSet) no longer exists (`NotFound`).
- The call times out.

When this happens, `threatguard remediate --live-k8s` prints:

```
Live Kubernetes ownership lookup unavailable; using safe fallback resolution.
```

This message is informational, not an error -- the command still completes
and still produces a (possibly manual-remediation) recommendation. The one
case that is authoritative even without a full owner chain is a live lookup
that *succeeds* and confirms a Pod has zero owner references: that is ground
truth (a genuine standalone Pod), so it is deliberately **not** re-guessed
against the naming heuristic.

## Observability

Each resolution result records which method produced it
(`owner_references` / `live_api` / `pod_name_pattern` / manual), for
operators auditing why a given command was or wasn't generated. This is
exposed only as data on the resolution result itself, not as a Prometheus
metric label -- Pod names and other per-workload identifiers are unbounded
cardinality and must never become metric labels (see
`reporting/cross_domain_metrics.py`'s existing bounded-severity-only
labeling convention).
