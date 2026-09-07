"""
ThreatGuard Forensic Evidence Collector & Audit Exporter.
Deterministically generates and exports:
- Normalized event streams (JSON lines)
- Correlated security incidents (JSON)
- Workload risk assessments (JSON)
- Visual attack chains (Mermaid + HTML)
- Executive security audit reports (HTML + Markdown)
Works seamlessly in live cluster environments and offline CI/testing pipelines.
"""

import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Any

from cloudnative_threatguard.config import settings
from cloudnative_threatguard.correlation.kubernetes import correlate_incidents
from cloudnative_threatguard.runtime.events import SecurityEvent

from .attack_chain import AttackChainVisualizer
from .incidents import IncidentManager
from .risk import RiskScoringEngine


class ForensicEvidenceCollector:
    def __init__(self, artifacts_dir: str | None = None, protected_namespace: str = "threatguard"):
        self.artifacts_dir = artifacts_dir or str(settings.ARTIFACTS_DIR)
        self.protected_namespace = protected_namespace
        self.risk_engine = RiskScoringEngine()
        self.incident_manager = IncidentManager()

    def ensure_directories(self):
        for sub in ["admission", "runtime", "incidents", "reports", "forensics"]:
            os.makedirs(os.path.join(self.artifacts_dir, sub), exist_ok=True)

    def collect_live_cluster_telemetry(self) -> dict[str, Any]:
        """Captures live logs and constraint statuses from Kubernetes if accessible."""
        cluster_info = {"status": "offline", "gatekeeper": None, "tetragon": None}
        try:
            res = subprocess.run(["kubectl", "cluster-info"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                cluster_info["status"] = "online"
                # Gatekeeper constraints
                gk_res = subprocess.run(["kubectl", "get", "constraints", "-o", "json"], capture_output=True, text=True, timeout=5)
                if gk_res.returncode == 0:
                    gk_data = json.loads(gk_res.stdout)
                    cluster_info["gatekeeper"] = gk_data
                    gk_file = os.path.join(self.artifacts_dir, "admission", "gatekeeper-status.json")
                    with open(gk_file, "w", encoding="utf-8") as f:
                        json.dump(gk_data, f, indent=2)

                # Tetragon logs
                tet_res = subprocess.run(["kubectl", "logs", "-A", "-l", "app.kubernetes.io/name=tetragon", "--tail=200"],
                                         capture_output=True, text=True, timeout=5)
                if tet_res.returncode == 0:
                    tet_log_file = os.path.join(self.artifacts_dir, "runtime", "tetragon-daemon.log")
                    with open(tet_log_file, "w", encoding="utf-8") as f:
                        f.write(tet_res.stdout)
        except Exception:
            pass
        return cluster_info

    def generate_evidence_package(
        self,
        security_events: list[SecurityEvent] | None = None,
        workload_spec: dict[str, Any] | None = None
    ) -> dict[str, str]:
        """
        Processes normalized events, correlates incidents, evaluates risk,
        and writes out all deterministic audit artifacts.
        """
        self.ensure_directories()
        generated_files = {}

        # Default synthetic events if none provided (e.g. for offline demonstration)
        if security_events is None:
            security_events = self._load_or_create_events()

        # 1. Export Normalized Event Stream (JSON Lines)
        norm_file = os.path.join(self.artifacts_dir, "runtime", "normalized-events.jsonl")
        with open(norm_file, "w", encoding="utf-8") as f:
            for ev in security_events:
                f.write(json.dumps(ev.to_dict()) + "\n")
        generated_files["normalized_events"] = norm_file

        # 2. Correlate Incidents
        raw_incidents = correlate_incidents(security_events)
        incident_dicts = []
        for r_inc in raw_incidents:
            # Register in incident manager
            inc = self.incident_manager.create_incident_from_correlation(r_inc)
            incident_dicts.append(inc)

        inc_file = os.path.join(self.artifacts_dir, "incidents", "correlated-incidents.json")
        with open(inc_file, "w", encoding="utf-8") as f:
            json.dump({"incidents": incident_dicts}, f, indent=2)
        generated_files["incidents"] = inc_file

        # 3. Workload Risk Assessment
        workload_ref = f"{self.protected_namespace}/threatguard-target-pod"
        risk_eval = self.risk_engine.evaluate_workload(
            events=security_events,
            workload_ref=workload_ref,
            workload_spec=workload_spec or {"privileged": False, "runAsUser": 0}
        )
        risk_file = os.path.join(self.artifacts_dir, "reports", "risk-assessments.json")
        with open(risk_file, "w", encoding="utf-8") as f:
            json.dump(risk_eval.to_dict(), f, indent=2)
        generated_files["risk_assessments"] = risk_file

        # 4. Visual Attack Chains (Mermaid + HTML)
        mermaid_file = os.path.join(self.artifacts_dir, "reports", "attack-chains.mmd")
        html_chain_file = os.path.join(self.artifacts_dir, "reports", "attack-chains.html")

        all_mermaid = []
        all_html_cards = []
        for inc in incident_dicts:
            viz = AttackChainVisualizer(incident=inc)
            all_mermaid.append(viz.to_mermaid())
            all_html_cards.append(viz.to_html_snippet())

        with open(mermaid_file, "w", encoding="utf-8") as f:
            f.write("\n\n".join(all_mermaid))
        generated_files["attack_chain_mermaid"] = mermaid_file

        with open(html_chain_file, "w", encoding="utf-8") as f:
            f.write("<!DOCTYPE html><html><head><title>ThreatGuard Attack Chains</title>"
                    "<style>body { background: #0f172a; color: #f8fafc; font-family: system-ui, -apple-system, sans-serif; padding: 2rem; }</style>"
                    "</head><body><h1>ThreatGuard Attack Progression Chains</h1>" +
                    "".join(all_html_cards) + "</body></html>")
        generated_files["attack_chain_html"] = html_chain_file

        # 5. Executive Security Audit Report (Markdown & HTML)
        md_file = os.path.join(self.artifacts_dir, "reports", "executive-audit-report.md")
        html_file = os.path.join(self.artifacts_dir, "reports", "executive-audit-report.html")

        md_content = self._render_executive_markdown(incident_dicts, risk_eval, len(security_events))
        with open(md_file, "w", encoding="utf-8") as f:
            f.write(md_content)
        generated_files["executive_md"] = md_file

        html_report = self._render_executive_html(incident_dicts, risk_eval, len(security_events))
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_report)
        generated_files["executive_html"] = html_file

        return generated_files

    def _load_or_create_events(self) -> list[SecurityEvent]:
        """Loads events from runtime-events.json or returns default verified simulation events."""
        runtime_json = os.path.join(self.artifacts_dir, "runtime", "runtime-events.json")
        events: list[SecurityEvent] = []
        if os.path.exists(runtime_json):
            try:
                with open(runtime_json, encoding="utf-8") as f:
                    raw = json.load(f)
                    for item in raw:
                        events.append(SecurityEvent.from_dict(item))
                    if events:
                        return events
            except Exception:
                pass

        # Deterministic simulation baseline events
        events.append(SecurityEvent.from_admission_denial(
            rule_id="RULE-K8S-009",
            policy_name="k8sprivilegedcontainer",
            resource_name="01-privileged-pod",
            namespace=self.protected_namespace,
            violation_message="Privileged container execution is prohibited"
        ))
        events.append(SecurityEvent.from_simulation(
            scenario_id="SCEN-001",
            name="Interactive Shell Execution",
            pod="threatguard-target-pod",
            namespace=self.protected_namespace,
            command="/bin/sh -c whoami",
            technique="T1059.004",
            tactic="Execution",
            severity="HIGH"
        ))
        events.append(SecurityEvent.from_simulation(
            scenario_id="SCEN-004",
            name="Sensitive Credential Access",
            pod="threatguard-target-pod",
            namespace=self.protected_namespace,
            command="cat /var/run/secrets/kubernetes.io/serviceaccount/token",
            technique="T1552.007",
            tactic="Credential Access",
            severity="CRITICAL"
        ))
        events.append(SecurityEvent.from_simulation(
            scenario_id="SCEN-006",
            name="Outbound C2 Network Connection",
            pod="threatguard-target-pod",
            namespace=self.protected_namespace,
            command="nc -zvw1 1.1.1.1 443",
            technique="T1071.001",
            tactic="Command and Control",
            severity="HIGH"
        ))
        return events

    def _render_executive_markdown(self, incidents: list[dict[str, Any]], risk_eval: Any, event_count: int) -> str:
        lines = [
            "# ThreatGuard Executive Security Audit Report",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Evaluation Scope:** Namespace `{self.protected_namespace}`",
            "",
            "## 1. Executive Summary",
            f"- **Telemetry Events Analyzed:** {event_count}",
            f"- **Correlated Incidents:** {len(incidents)}",
            f"- **Workload Composite Risk Score:** {risk_eval.composite_risk_score:.1f} / 100 ({risk_eval.risk_tier})",
            "",
            "## 2. Correlated Incidents Overview",
            "| Incident ID | Severity | Status | Workload | MITRE Tactics | Primary Technique |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |"
        ]
        for inc in incidents:
            tactics = ", ".join(inc.get("tactics", []))
            techniques = inc.get("techniques", [])
            tech = techniques[0] if techniques else "N/A"
            lines.append(f"| `{inc.get('incident_id')}` | **{inc.get('severity')}** | {inc.get('status')} | `{inc.get('affected_namespace')}/{inc.get('affected_pod')}` | {tactics} | `{tech}` |")

        lines.extend([
            "",
            "## 3. Workload Risk Contributors",
            "| Factor | Impact | Description |",
            "| :--- | :--- | :--- |"
        ])
        for c in risk_eval.top_risk_contributors:
            lines.append(f"| **{c.factor_name}** | +{c.impact_points:.1f} pts | {c.description} |")

        lines.extend([
            "",
            "## 4. Recommended Security Actions",
            "1. **Enforce Baseline Pod Security Standards:** Restrict privileged escalation and host path mounts at admission.",
            "2. **Deploy Zero-Trust NetworkPolicies:** Quarantine breached workloads to contain lateral spread.",
            "3. **Rotate ServiceAccount Tokens:** Regularly audit token mount permissions and invalidate compromised tokens.",
            ""
        ])
        return "\n".join(lines)

    def _render_executive_html(self, incidents: list[dict[str, Any]], risk_eval: Any, event_count: int) -> str:
        tier_color = "#ef4444" if risk_eval.risk_tier == "CRITICAL" else "#f97316"
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ThreatGuard Executive Security Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b1120; color: #e2e8f0; margin: 0; padding: 2rem; }}
    .header {{ border-bottom: 2px solid #1e293b; padding-bottom: 1.5rem; margin-bottom: 2rem; }}
    .badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-weight: bold; font-size: 0.875rem; }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }}
    .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #f97316; border: 1px solid #f97316; }}
    .card {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
    th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #334155; }}
    th {{ background: #0f172a; color: #38bdf8; font-size: 0.875rem; text-transform: uppercase; }}
    .score {{ font-size: 2.5rem; font-weight: 800; color: {tier_color}; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>ThreatGuard Kubernetes Security Platform</h1>
    <p>Executive Security Posture & Incident Audit Report | Scope: <code>{self.protected_namespace}</code></p>
  </div>

  <div class="card">
    <h2>Workload Risk Posture Score</h2>
    <div class="score">{risk_eval.composite_risk_score:.1f} / 100 <span class="badge badge-critical">{risk_eval.risk_tier}</span></div>
    <p>Composite risk computed across telemetry severity, attack chain depth, and workload configuration.</p>
  </div>

  <div class="card">
    <h2>Correlated Incidents ({len(incidents)})</h2>
    <table>
      <tr>
        <th>Incident ID</th>
        <th>Severity</th>
        <th>Status</th>
        <th>Workload</th>
        <th>Tactics</th>
      </tr>
"""
        for inc in incidents:
            sev = inc.get("severity", "MEDIUM")
            badge_cls = "badge-critical" if sev == "CRITICAL" else "badge-high"
            html += f"""
      <tr>
        <td><code>{inc.get('incident_id')}</code></td>
        <td><span class="badge {badge_cls}">{sev}</span></td>
        <td>{inc.get('status')}</td>
        <td>{inc.get('affected_namespace')}/{inc.get('affected_pod')}</td>
        <td>{', '.join(inc.get('tactics', []))}</td>
      </tr>
"""
        html += """
    </table>
  </div>
</body>
</html>"""
        return html


def main() -> int:
    collector = ForensicEvidenceCollector()
    print("[*] Collecting live Kubernetes telemetry (if reachable)...")
    collector.collect_live_cluster_telemetry()
    print("[*] Generating consolidated forensic evidence package...")
    files = collector.generate_evidence_package()
    for name, path in files.items():
        print(f" [+] Generated {name:<22}: {os.path.relpath(path, settings.PROJECT_ROOT)}")
    print("[OK] Evidence collection and report export completed successfully.")
    return 0
