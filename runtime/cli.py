"""
CloudNative ThreatGuard Operator CLI.
Interactive and scriptable command-line interface for security operations,
incident investigation, attack chain inspection, risk triage, and attack simulation.
"""

import sys
import os
import json
import argparse
import subprocess
from typing import Optional, List, Dict, Any

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from runtime.engine.incident_engine import IncidentManager, IncidentStatus
from runtime.engine.risk_engine import RiskScoringEngine
from runtime.engine.attack_chain import AttackChainVisualizer
from runtime.engine.recommendations import ResponseRecommendationEngine
from runtime.engine.models import SecurityEvent, Severity


class ThreatGuardCLI:
    def __init__(self, state_file: Optional[str] = None):
        self.state_file = state_file or os.path.join(PROJECT_ROOT, "artifacts", "threatguard-state.json")
        self.incident_manager = IncidentManager()
        self.risk_engine = RiskScoringEngine()
        self.recommendation_engine = ResponseRecommendationEngine()
        self._load_state()

    def _load_state(self):
        """Loads persistent incident state if present."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
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

        # Check cluster
        k8s_ok = False
        try:
            res = subprocess.run(["kubectl", "cluster-info"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            k8s_ok = res.returncode == 0
        except Exception:
            pass
        print(f"[*] Kubernetes API Server:       {'[ONLINE]' if k8s_ok else '[OFFLINE / UNREACHABLE]'}")

        # Check Gatekeeper
        gk_ok = False
        if k8s_ok:
            try:
                res = subprocess.run(["kubectl", "get", "pods", "-n", "gatekeeper-system", "-l", "control-plane=controller-manager"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
                gk_ok = "Running" in res.stdout
            except Exception:
                pass
        print(f"[*] OPA Gatekeeper Controller:   {'[ACTIVE]' if gk_ok else '[NOT RUNNING / STANDBY]'}")

        # Check Tetragon
        tet_ok = False
        if k8s_ok:
            try:
                res = subprocess.run(["kubectl", "get", "pods", "-n", "kube-system", "-l", "app.kubernetes.io/name=tetragon"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
                tet_ok = "Running" in res.stdout
            except Exception:
                pass
        print(f"[*] Tetragon eBPF Sensor:        {'[ACTIVE]' if tet_ok else '[NOT RUNNING / STANDBY]'}")

        # Incident Manager
        inc_count = len(self.incident_manager.incidents)
        print(f"[*] Active Incidents Tracked:    {inc_count}")
        print(f"[*] Detection Engine Rules:      10 Active Rules (RULE-K8S-001..010)")
        print(f"[*] Telemetry Normalization:     Normalized SecurityEvent v2")
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
                techs = ", ".join(inc.get("mitre_techniques", [])[:3])
                print(f"{inc.get('incident_id'):<16} {inc.get('severity'):<10} {inc.get('status'):<14} {inc.get('pod_name', ''):<24} {techs:<20}")
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
        print(f"Target Pod:  {inc.get('pod_name')} (Namespace: {inc.get('namespace')})")
        print(f"Tactics:     {', '.join(inc.get('mitre_tactics', []))}")
        print(f"Techniques:  {', '.join(inc.get('mitre_techniques', []))}")
        print(f"Description: {inc.get('description')}")
        print("")

        visualizer = AttackChainVisualizer(incident=inc)
        if args.format == "mermaid":
            print("--- ATTACK CHAIN (MERMAID) ---")
            print(visualizer.to_mermaid())
        elif args.format == "json":
            print(visualizer.to_json())
        else:
            print("--- ATTACK CHAIN TIMELINE ---")
            print(visualizer.to_ascii())

        print("\n--- RECOMMENDED REMEDIATIONS ---")
        for rec in inc.get("recommended_actions", []):
            print(f"[{rec.get('priority', 'HIGH')}] {rec.get('title')}")
            print(f"  Rationale: {rec.get('rationale', rec.get('description', ''))}")
            if rec.get("execution_command"):
                print(f"  Remediation Command:\n    {rec.get('execution_command')}")
            print("")
        return 0

    def cmd_workloads_list(self, args) -> int:
        """Calculates and displays risk posture across workloads."""
        print("============================================================")
        print("  THREATGUARD WORKLOAD RISK POSTURE")
        print("============================================================")
        print(f"{'WORKLOAD':<32} {'RISK SCORE':<12} {'TIER':<10} {'EVENTS':<8}")
        print("-" * 65)

        # Aggregate events by workload
        workload_events: Dict[str, List[SecurityEvent]] = {}
        for inc in self.incident_manager.incidents.values():
            workload_ref = f"{inc.get('namespace')}/{inc.get('pod_name')}"
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
        sim_dir = os.path.join(PROJECT_ROOT, "simulations")
        runner = os.path.join(sim_dir, "run_simulations.sh")

        if args.scenario == "all":
            print("[*] Launching Full Simulation Suite...")
            res = subprocess.run(["bash", runner], cwd=PROJECT_ROOT)
            return res.returncode
        else:
            scen_file = os.path.join(sim_dir, "scenarios", f"{args.scenario}.sh")
            if not os.path.exists(scen_file):
                # Try prefixing scen_
                scen_file = os.path.join(sim_dir, "scenarios", f"scen_{args.scenario}.sh")
            if not os.path.exists(scen_file):
                print(f"[ERROR] Simulation scenario script not found: {args.scenario}")
                return 1
            print(f"[*] Executing Simulation Scenario: {os.path.basename(scen_file)}")
            res = subprocess.run(["bash", scen_file], cwd=PROJECT_ROOT)
            return res.returncode

    def cmd_remediate(self, args) -> int:
        """Generates dry-run safe remediation commands for an incident."""
        inc = self.incident_manager.get_incident(args.incident_id)
        if not inc:
            print(f"[ERROR] Incident '{args.incident_id}' not found.")
            return 1

        pod_name = inc.get("pod_name", "target-pod")
        namespace = inc.get("namespace", "threatguard")
        techniques = inc.get("mitre_techniques", [])
        severity = inc.get("severity", "HIGH")

        recs = self.recommendation_engine.generate_recommendations(
            namespace=namespace,
            pod_name=pod_name,
            techniques=techniques,
            severity=severity
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
                print(f"[*] Executing command on cluster...")
                subprocess.run(r.execution_command, shell=True)
        return 0

    def cmd_report_export(self, args) -> int:
        """Exports a consolidated incident & security audit report."""
        output_path = args.output or os.path.join(PROJECT_ROOT, "artifacts", "threatguard-audit-report.json")
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
                    f"<td>{inc.get('namespace')}/{inc.get('pod_name')}</td>"
                    f"<td>{inc.get('status')}</td>"
                    f"<td>{', '.join(inc.get('mitre_tactics', []))}</td></tr>"
                )
            html_content += "</table></body></html>"
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
        else:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

        print(f"[+] Successfully exported security audit report to: {output_path}")
        return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="threatguard", description="CloudNative ThreatGuard Operator CLI")
    subparsers = parser.add_subparsers(dest="subcommand", help="Command to execute")

    # status
    subparsers.add_parser("status", help="Show ThreatGuard stack & cluster status")

    # incidents
    inc_parser = subparsers.add_parser("incidents", help="Manage security incidents")
    inc_sub = inc_parser.add_subparsers(dest="inc_command", help="Incident action")

    # incidents list
    inc_list = inc_sub.add_parser("list", help="List active & historical incidents")
    inc_list.add_argument("--status", choices=["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED"], help="Filter by status")
    inc_list.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Filter by severity")

    # incidents show
    inc_show = inc_sub.add_parser("show", help="Show incident timeline and attack chain")
    inc_show.add_argument("incident_id", help="Incident ID (e.g. #TG-123456)")
    inc_show.add_argument("--format", choices=["ascii", "mermaid", "json"], default="ascii", help="Attack chain format")

    # workloads list
    subparsers.add_parser("workloads", help="List workload risk postures")

    # simulate
    sim_parser = subparsers.add_parser("simulate", help="Run attack simulation scenarios")
    sim_parser.add_argument("scenario", default="all", nargs="?", help="Scenario to run (e.g. 001_shell_execution or 'all')")

    # remediate
    rem_parser = subparsers.add_parser("remediate", help="View or apply incident remediation commands")
    rem_parser.add_argument("incident_id", help="Incident ID")
    rem_parser.add_argument("--dry-run", action="store_true", default=True, help="Print dry-run commands (default: True)")
    rem_parser.add_argument("--apply", action="store_true", help="Execute commands on cluster (requires explicit flag)")

    # report export
    rep_parser = subparsers.add_parser("report", help="Export audit report")
    rep_parser.add_argument("--output", help="Destination file path (.json or .html)")

    return parser


def main(args=None):
    parser = build_parser()
    parsed_args = parser.parse_args(args)
    cli = ThreatGuardCLI()

    if not parsed_args.subcommand:
        parser.print_help()
        return 0

    if parsed_args.subcommand == "status":
        return cli.cmd_status(parsed_args)
    elif parsed_args.subcommand == "incidents":
        if parsed_args.inc_command == "show":
            return cli.cmd_incidents_show(parsed_args)
        else:
            return cli.cmd_incidents_list(parsed_args)
    elif parsed_args.subcommand == "workloads":
        return cli.cmd_workloads_list(parsed_args)
    elif parsed_args.subcommand == "simulate":
        return cli.cmd_simulate(parsed_args)
    elif parsed_args.subcommand == "remediate":
        return cli.cmd_remediate(parsed_args)
    elif parsed_args.subcommand == "report":
        return cli.cmd_report_export(parsed_args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
