# Security Policy

## What this project is

CloudNative ThreatGuard is a **security research and engineering lab**, not a production security
product. It demonstrates a Kubernetes defense-in-depth architecture (OPA Gatekeeper admission control +
Cilium Tetragon eBPF runtime detection) and a cross-domain (AWS IAM + Kubernetes) correlation engine,
and is intended for:

- Learning and portfolio purposes
- Local security engineering experimentation (KIND clusters, isolated lab namespaces)
- Reference architecture for defense-in-depth Kubernetes security design

It is **not** intended to be deployed as-is to protect production workloads. If you adapt it for
production use, you are responsible for your own threat modeling, hardening review, and operational
monitoring beyond what this repository provides.

## Supported versions

This is a single-track project without long-term-support branches. Security fixes are made against
the `main`/`dev` branches only; there are no maintained release branches to backport to.

| Version | Supported |
| ------- | --------- |
| latest on `main`/`dev` | Yes |
| anything else | No |

## What is intentionally simulated

Several components in this repository deliberately model attacker behavior for demonstration and
detection-testing purposes. None of this is destructive, and none of it should be run outside the
isolated local environments described below:

- **`simulations/`** -- shell scripts and Kubernetes manifests that spawn shells, run reconnaissance
  binaries, read (test) credential files, and open outbound connections inside a disposable, local KIND
  cluster's `threatguard`/`threatguard-lab` namespaces, so the Tetragon detection rules and correlation
  engine have real telemetry to react to.
- **`src/cloudnative_threatguard/correlation/cross_domain/demo/`** -- a fully deterministic, **offline**
  demonstration of a cross-domain "cloud identity to Kubernetes pod" kill chain. It requires zero AWS
  credentials and makes zero network calls; all data is synthetic and labeled `[DEMO]`/`SIMULATED_DEMO_DATA`.
- **`deploy/gatekeeper/tests/manifests/negative/`** -- intentionally insecure Kubernetes manifests
  (privileged containers, host mounts, etc.) used only to prove the admission policies reject them.

None of these scripts or manifests target anything other than a local, disposable KIND cluster you
control. Do not point the simulation scripts at a shared or production cluster.

## Reporting a vulnerability

If you find a security issue in this repository itself (e.g., a way the admission policies can be
bypassed, a genuine command-injection path, a credential handling flaw -- as distinct from the
intentionally-simulated attacker behavior described above), please report it privately rather than
opening a public issue:

- Open a [GitHub Security Advisory](https://github.com/cloudnative-threatguard/cloudnative-threatguard/security/advisories/new)
  on this repository, or
- If that isn't available to you, open an issue asking a maintainer to contact you privately, without
  including exploit details in the issue itself.

Please include: the affected file(s)/component, a description of the issue and its impact, and
reproduction steps. We aim to acknowledge reports within a few days; given this is a community/portfolio
project rather than a funded security team, response and fix timelines are best-effort.

## Responsible use

Do not use the techniques demonstrated in `simulations/` or the Tetragon/Gatekeeper detection logic
against systems you do not own or do not have explicit authorization to test.
