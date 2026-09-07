"""
CloudNative ThreatGuard Operator CLI.
Interactive and scriptable command-line interface for security operations,
incident investigation, attack chain inspection, risk triage, attack
simulation, admission validation, platform verification, and the offline
cross-domain demo.

This is the single canonical entry point for the project (installed as
``threatguard`` via ``[project.scripts]`` in pyproject.toml). It replaces
the previous threatguard/threatguard.py launcher pair, verify-all.py/.sh,
run_tests.py, demo-cloud-security.py, and
policies/gatekeeper/tests/validate_admission_manifests.py.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from cloudnative_threatguard.config import settings
from cloudnative_threatguard.reporting.attack_chain import AttackChainVisualizer
from cloudnative_threatguard.reporting.incidents import IncidentManager
from cloudnative_threatguard.reporting.recommendations import ResponseRecommendationEngine
from cloudnative_threatguard.reporting.risk import RiskScoringEngine
from cloudnative_threatguard.reporting.workload_resolver import KubectlOwnershipClient, resolve_workload_owner
from cloudnative_threatguard.runtime.events import SecurityEvent


class ThreatGuardCLI:
    def __init__(self, state_file: str | None = None):
        self.state_file = state_file or str(settings.CLI_STATE_FILE)
        self.incident_manager = IncidentManager()
        self.risk_engine = RiskScoringEngine()
        self.recommendation_engine = ResponseRecommendationEngine()
        self._load_state()

    def _load_state(self):
        """Loads persistent incident state if present."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, encoding="utf-8") as f:
                    data = json.load(f)
                    self.incident_manager.incidents = data.get("incidents", {})
                    self.incident_manager.audit_log = data.get("audit_log", [])
            except Exception:
                pass

    def _save_state(self):
        """Saves persistent incident state."""
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump({
                "incidents": self.incident_manager.incidents,
                "audit_log": self.incident_manager.audit_log
            }, f, indent=2)

    def cmd_status(self, args) -> int:
        """Inspects status of the ThreatGuard stack and cluster services."""
        print("============================================================")
        print("  CLOUDNATIVE THREATGUARD: SYSTEM STATUS")
        print("============================================================")

        k8s_ok = False
        try:
            res = subprocess.run(["kubectl", "cluster-info"], capture_output=True, text=True, timeout=5)
            k8s_ok = res.returncode == 0
        except Exception:
            pass
        print(f"[*] Kubernetes API Server:       {'[ONLINE]' if k8s_ok else '[OFFLINE / UNREACHABLE]'}")

        gk_ok = False
        if k8s_ok:
            try:
                res = subprocess.run(["kubectl", "get", "pods", "-n", "gatekeeper-system", "-l", "control-plane=controller-manager"],
                                     capture_output=True, text=True, timeout=5)
                gk_ok = "Running" in res.stdout
            except Exception:
                pass
        print(f"[*] OPA Gatekeeper Controller:   {'[ACTIVE]' if gk_ok else '[NOT RUNNING / STANDBY]'}")

        tet_ok = False
        if k8s_ok:
            try:
                res = subprocess.run(["kubectl", "get", "pods", "-A", "-l", "app.kubernetes.io/name=tetragon"],
                                     capture_output=True, text=True, timeout=5)
                tet_ok = "Running" in res.stdout
            except Exception:
                pass
        print(f"[*] Tetragon eBPF Sensor:        {'[ACTIVE]' if tet_ok else '[NOT RUNNING / STANDBY]'}")

        inc_count = len(self.incident_manager.incidents)
        print(f"[*] Active Incidents Tracked:    {inc_count}")
        print("[*] Detection Engine Rules:      11 Active Rules (RUNTIME-001..007, RULE-K8S-007..009)")
        print("[*] Telemetry Normalization:     Normalized SecurityEvent v2")
        print("============================================================")
        return 0

    def cmd_incidents_list(self, args) -> int:
        """Lists incidents with optional filtering."""
        incidents = self.incident_manager.list_incidents(
            status=args.status,
            severity=args.severity
        )
        print("==========================================================================================")
        print(f"  THREATGUARD INCIDENT QUEUE ({len(incidents)} Incidents)")
        print("==========================================================================================")
        print(f"{'INCIDENT ID':<16} {'SEVERITY':<10} {'STATUS':<14} {'POD':<24} {'TECHNIQUES':<20}")
        print("-" * 90)
        if not incidents:
            print("  No incidents found matching criteria.")
        else:
            for inc in incidents:
                techs = ", ".join(inc.get("techniques", [])[:3])
                print(f"{inc.get('incident_id'):<16} {inc.get('severity'):<10} {inc.get('status'):<14} {inc.get('affected_pod', ''):<24} {techs:<20}")
        print("==========================================================================================")
        return 0

    def cmd_incidents_show(self, args) -> int:
        """Displays details, timeline, and attack chain for an incident."""
        inc = self.incident_manager.get_incident(args.incident_id)
        if not inc:
            print(f"[ERROR] Incident '{args.incident_id}' not found.")
            return 1

        print("============================================================")
        print(f"  INCIDENT DETAILS: {inc.get('incident_id')}")
        print("============================================================")
        print(f"Title:       {inc.get('title')}")
        print(f"Severity:    {inc.get('severity')}")
        print(f"Status:      {inc.get('status')}")
        print(f"Target Pod:  {inc.get('affected_pod')} (Namespace: {inc.get('affected_namespace')})")
        print(f"Tactics:     {', '.join(inc.get('tactics', []))}")
        print(f"Techniques:  {', '.join(inc.get('techniques', []))}")
        print(f"Summary:     {inc.get('metadata', {}).get('summary', '')}")
        print("")

        visualizer = AttackChainVisualizer(incident=inc)
        if args.format == "mermaid":
            print("--- ATTACK CHAIN (MERMAID) ---")
            print(visualizer.to_mermaid())
        elif args.format == "json":
            print(visualizer.to_json())
        else:
            print("--- ATTACK CHAIN TIMELINE ---")
            timeline = visualizer.to_ascii()
            try:
                print(timeline)
            except UnicodeEncodeError:
                safe_timeline = (
                    timeline.replace("▼", "v")
                    .replace("╔", "+").replace("═", "=").replace("╗", "+")
                    .replace("║", "|").replace("╚", "+").replace("╝", "+")
                    .replace("┌", "+").replace("─", "-").replace("│", "|")
                    .replace("└──", "+--")
                )
                print(safe_timeline)

        print("\n--- RECOMMENDED REMEDIATIONS ---")
        for rec in inc.get("recommendations", []):
            print(f"[{rec.get('priority', 'HIGH')}] {rec.get('title')}")
            print(f"  Rationale: {rec.get('rationale', '')}")
            if rec.get("dry_run_command"):
                print(f"  Dry-Run Command:\n    {rec.get('dry_run_command')}")
            print("")
        return 0

    def cmd_workloads_list(self, args) -> int:
        """Calculates and displays risk posture across workloads."""
        print("============================================================")
        print("  THREATGUARD WORKLOAD RISK POSTURE")
        print("============================================================")
        print(f"{'WORKLOAD':<32} {'RISK SCORE':<12} {'TIER':<10} {'EVENTS':<8}")
        print("-" * 65)

        workload_events: dict[str, list[SecurityEvent]] = {}
        for inc in self.incident_manager.incidents.values():
            workload_ref = f"{inc.get('affected_namespace')}/{inc.get('affected_pod')}"
            workload_events.setdefault(workload_ref, [])
            for ev_dict in inc.get("events", []):
                workload_events[workload_ref].append(SecurityEvent.from_dict(ev_dict))

        if not workload_events:
            print("  No workloads currently have active telemetry events recorded.")
        else:
            for wref, evs in workload_events.items():
                assessment = self.risk_engine.evaluate_workload(evs, workload_ref=wref)
                print(f"{wref:<32} {assessment.composite_risk_score:<12.1f} {assessment.risk_tier:<10} {len(evs):<8}")
        print("============================================================")
        return 0

    def cmd_simulate(self, args) -> int:
        """Runs attack simulation scenarios."""
        sim_dir = settings.PROJECT_ROOT / "simulations"
        runner = sim_dir / "run_simulations.sh"

        if args.scenario == "all":
            print("[*] Launching Full Simulation Suite...")
            res = subprocess.run(["bash", str(runner)], cwd=str(settings.PROJECT_ROOT))
            return res.returncode
        scen_file = sim_dir / "scenarios" / f"{args.scenario}.sh"
        if not scen_file.exists():
            scen_file = sim_dir / "scenarios" / f"scen_{args.scenario}.sh"
        if not scen_file.exists():
            print(f"[ERROR] Simulation scenario script not found: {args.scenario}")
            return 1
        print(f"[*] Executing Simulation Scenario: {scen_file.name}")
        res = subprocess.run(["bash", str(scen_file)], cwd=str(settings.PROJECT_ROOT))
        return res.returncode

    def cmd_remediate(self, args) -> int:
        """Generates dry-run safe remediation commands for an incident."""
        inc = self.incident_manager.get_incident(args.incident_id)
        if not inc:
            print(f"[ERROR] Incident '{args.incident_id}' not found.")
            return 1

        pod_name = inc.get("affected_pod", "target-pod")
        namespace = inc.get("affected_namespace", "threatguard")
        techniques = inc.get("techniques", [])
        severity = inc.get("severity", "HIGH")

        # Live Kubernetes ownership lookup is entirely opt-in (--live-k8s):
        # every other ThreatGuard function, including remediate without this
        # flag, works with no kubeconfig at all.
        kubernetes_client = KubectlOwnershipClient() if getattr(args, "live_k8s", False) else None
        if kubernetes_client is not None:
            probe = resolve_workload_owner(namespace, pod_name, kubernetes_client=kubernetes_client)
            if probe.live_lookup_status == "failed":
                print("[!] Live Kubernetes ownership lookup unavailable; using safe fallback resolution.")

        recs = self.recommendation_engine.generate_recommendations(
            namespace=namespace,
            pod_name=pod_name,
            techniques=techniques,
            severity=severity,
            kubernetes_client=kubernetes_client,
        )

        print("============================================================")
        print(f"  REMEDIATION PLAYBOOK: {args.incident_id} ({'DRY-RUN MODE' if args.dry_run else 'APPLY MODE'})")
        print("============================================================")
        for r in recs:
            print(f"\n[{r.priority}] {r.title}")
            print(f"Category:     {r.category}")
            print(f"Blast Radius: {r.blast_radius}")
            print(f"Reversible:   {r.reversibility}")
            cmd = r.dry_run_command if args.dry_run else r.execution_command
            print("Command:")
            print("------------------------------------------------------------")
            print(cmd)
            print("------------------------------------------------------------")

            if not args.dry_run and args.apply:
                print("[*] Executing command on cluster...")
                subprocess.run(r.execution_command, shell=True)
        return 0

    def cmd_report_incidents(self, args) -> int:
        """Exports a consolidated incident & security audit report."""
        output_path = args.output or str(settings.ARTIFACTS_DIR / "threatguard-audit-report.json")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        report = {
            "title": "ThreatGuard Kubernetes Security Audit Report",
            "incidents_total": len(self.incident_manager.incidents),
            "incidents": list(self.incident_manager.incidents.values()),
            "audit_log": self.incident_manager.audit_log
        }

        if output_path.endswith(".html"):
            html_content = (
                "<!DOCTYPE html><html><head><title>ThreatGuard Audit Report</title>"
                "<style>body { font-family: sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }"
                "table { width: 100%; border-collapse: collapse; margin-top: 20px; }"
                "th, td { border: 1px solid #334155; padding: 10px; text-align: left; }"
                "th { background: #1e293b; color: #38bdf8; }"
                ".critical { color: #ef4444; font-weight: bold; }"
                ".high { color: #f97316; font-weight: bold; }"
                "</style></head><body>"
                "<h1>ThreatGuard Kubernetes Security Audit Report</h1>"
                f"<p>Total Incidents Detected: {len(report['incidents'])}</p>"
                "<table><tr><th>ID</th><th>Severity</th><th>Workload</th><th>Status</th><th>Tactics</th></tr>"
            )
            for inc in report["incidents"]:
                sev_cls = "critical" if inc.get("severity") == "CRITICAL" else "high"
                html_content += (
                    f"<tr><td>{inc.get('incident_id')}</td>"
                    f"<td class='{sev_cls}'>{inc.get('severity')}</td>"
                    f"<td>{inc.get('affected_namespace')}/{inc.get('affected_pod')}</td>"
                    f"<td>{inc.get('status')}</td>"
                    f"<td>{', '.join(inc.get('tactics', []))}</td></tr>"
                )
            html_content += "</table></body></html>"
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
        else:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

        print(f"[+] Successfully exported security audit report to: {output_path}")
        return 0

    def cmd_report_scorecard(self, args) -> int:
        """Computes and prints the admission/runtime security scorecard."""
        from cloudnative_threatguard.reporting import scorecard
        report = scorecard.generate_scorecard()
        written = scorecard.write_scorecard(report)
        scorecard.print_summary(report)
        for path in written:
            print(f"[+] Security report written to: {path}")
        return 0 if report["overall_status"] == "PASS" else 1

    def cmd_report_evidence(self, args) -> int:
        """Generates the full forensic evidence package (JSONL/incidents/risk/HTML/MD)."""
        from cloudnative_threatguard.reporting.evidence import ForensicEvidenceCollector
        collector = ForensicEvidenceCollector()
        print("[*] Collecting live Kubernetes telemetry (if reachable)...")
        collector.collect_live_cluster_telemetry()
        print("[*] Generating consolidated forensic evidence package...")
        files = collector.generate_evidence_package()
        for name, path in files.items():
            print(f" [+] Generated {name:<22}: {os.path.relpath(path, settings.PROJECT_ROOT)}")
        print("[OK] Evidence collection and report export completed successfully.")
        return 0

    def cmd_admission_validate(self, args) -> int:
        """Validates positive/negative Gatekeeper admission manifests via OPA."""
        from cloudnative_threatguard.admission.validator import print_report, validate_all
        report = validate_all()
        print_report(report)
        return 0 if report.all_passed else 1

    def cmd_verify(self, args) -> int:
        """Runs the full end-to-end platform verification."""
        from cloudnative_threatguard.cli.verify import run_verification
        return run_verification()

    def cmd_demo_cross_domain(self, args) -> int:
        """Runs the deterministic, offline cross-domain (CloudGraphGuard + ThreatGuard) demo."""
        from cloudnative_threatguard.correlation.cross_domain.demo.deterministic_demo import run_deterministic_demo
        run_deterministic_demo()
        return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="threatguard", description="CloudNative ThreatGuard Operator CLI")
    subparsers = parser.add_subparsers(dest="subcommand", help="Command to execute")

    subparsers.add_parser("status", help="Show ThreatGuard stack & cluster status")

    inc_parser = subparsers.add_parser("incidents", help="Manage security incidents")
    inc_sub = inc_parser.add_subparsers(dest="inc_command", help="Incident action")

    inc_list = inc_sub.add_parser("list", help="List active & historical incidents")
    inc_list.add_argument("--status", choices=["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED"], help="Filter by status")
    inc_list.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Filter by severity")

    inc_show = inc_sub.add_parser("show", help="Show incident timeline and attack chain")
    inc_show.add_argument("incident_id", help="Incident ID (e.g. #TG-123456)")
    inc_show.add_argument("--format", choices=["ascii", "mermaid", "json"], default="ascii", help="Attack chain format")

    subparsers.add_parser("workloads", help="List workload risk postures")

    sim_parser = subparsers.add_parser("simulate", help="Run attack simulation scenarios")
    sim_parser.add_argument("scenario", default="all", nargs="?", help="Scenario to run (e.g. 001_shell_execution or 'all')")

    rem_parser = subparsers.add_parser("remediate", help="View or apply incident remediation commands")
    rem_parser.add_argument("incident_id", help="Incident ID")
    rem_parser.add_argument("--dry-run", action="store_true", default=True, help="Print dry-run commands (default: True)")
    rem_parser.add_argument("--apply", action="store_true", help="Execute commands on cluster (requires explicit flag)")
    rem_parser.add_argument(
        "--live-k8s", action="store_true",
        help="Resolve Pod ownership via a live 'kubectl' lookup (read-only) instead of naming-pattern inference alone. "
             "Optional; requires a working kubeconfig. Falls back safely if the lookup fails.",
    )

    rep_parser = subparsers.add_parser("report", help="Export audit reports and scorecards")
    rep_sub = rep_parser.add_subparsers(dest="rep_command", help="Report type")
    rep_incidents = rep_sub.add_parser("incidents", help="Export consolidated incident audit report (default)")
    rep_incidents.add_argument("--output", help="Destination file path (.json or .html)")
    rep_sub.add_parser("scorecard", help="Compute and print the admission/runtime security scorecard")
    rep_sub.add_parser("evidence", help="Generate the full forensic evidence package")

    adm_parser = subparsers.add_parser("admission", help="Admission-control operations")
    adm_sub = adm_parser.add_subparsers(dest="adm_command", help="Admission action")
    adm_sub.add_parser("validate", help="Validate positive/negative manifests against Gatekeeper Rego policies")

    subparsers.add_parser("verify", help="Run the full end-to-end platform verification")

    demo_parser = subparsers.add_parser("demo", help="Run offline demonstrations")
    demo_sub = demo_parser.add_subparsers(dest="demo_command", help="Demo to run")
    demo_sub.add_parser("cross-domain", help="Deterministic CloudGraphGuard + ThreatGuard cross-domain kill-chain demo")

    return parser


def main(args=None) -> int:
    parser = build_parser()
    parsed_args = parser.parse_args(args)
    cli = ThreatGuardCLI()

    if not parsed_args.subcommand:
        parser.print_help()
        return 0

    if parsed_args.subcommand == "status":
        return cli.cmd_status(parsed_args)
    if parsed_args.subcommand == "incidents":
        if parsed_args.inc_command == "show":
            return cli.cmd_incidents_show(parsed_args)
        return cli.cmd_incidents_list(parsed_args)
    if parsed_args.subcommand == "workloads":
        return cli.cmd_workloads_list(parsed_args)
    if parsed_args.subcommand == "simulate":
        return cli.cmd_simulate(parsed_args)
    if parsed_args.subcommand == "remediate":
        return cli.cmd_remediate(parsed_args)
    if parsed_args.subcommand == "report":
        if parsed_args.rep_command == "scorecard":
            return cli.cmd_report_scorecard(parsed_args)
        if parsed_args.rep_command == "evidence":
            return cli.cmd_report_evidence(parsed_args)
        return cli.cmd_report_incidents(parsed_args)
    if parsed_args.subcommand == "admission":
        if parsed_args.adm_command == "validate":
            return cli.cmd_admission_validate(parsed_args)
        return 0
    if parsed_args.subcommand == "verify":
        return cli.cmd_verify(parsed_args)
    if parsed_args.subcommand == "demo":
        if parsed_args.demo_command == "cross-domain":
            return cli.cmd_demo_cross_domain(parsed_args)
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
