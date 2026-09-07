"""
ThreatGuard Attack Chain Visualization Engine.
Transforms correlated security incidents and event sequences into multi-format attack chain graphs:
- Structured JSON graph (nodes, edges, evidence)
- Mermaid flowchart markdown
- Terminal ASCII/Unicode timeline
- Standalone HTML/CSS graphical component
"""

import html
from typing import Any


class AttackChainVisualizer:
    """
    Constructs multi-format visualizations of Kubernetes attack progression chains.
    """
    def __init__(self, incident: dict[str, Any]):
        self.incident = incident
        self.incident_id = incident.get("incident_id", "#TG-UNKNOWN")
        self.title = incident.get("title", "Security Incident")
        self.severity = incident.get("severity", "MEDIUM")
        self.pod = incident.get("affected_pod", "unknown-pod")
        self.namespace = incident.get("affected_namespace", "default")
        self.events = incident.get("events", [])
        self.nodes = self._extract_nodes()

    def _extract_nodes(self) -> list[dict[str, Any]]:
        nodes = []
        # If incident already has structured attack_chain, use it
        if "attack_chain" in self.incident and self.incident["attack_chain"]:
            for idx, raw in enumerate(self.incident["attack_chain"]):
                nodes.append({
                    "id": raw.get("node_id", f"step-{idx+1}"),
                    "step": raw.get("step", idx + 1),
                    "tactic": raw.get("tactic", "Execution"),
                    "technique": raw.get("technique", "T1059"),
                    "label": raw.get("label", "Security Action"),
                    "process": raw.get("process", ""),
                    "severity": raw.get("severity", "MEDIUM"),
                    "timestamp": raw.get("timestamp", ""),
                    "evidence": raw.get("evidence", {})
                })
            return nodes

        # Otherwise synthesize from raw events
        for idx, ev in enumerate(self.events):
            tactic = ev.get("mitre_tactic") or "Execution"
            technique = ev.get("mitre_technique") or "T1059"
            label = ev.get("description") or ev.get("action") or f"Event {idx+1}"
            nodes.append({
                "id": f"step-{idx+1}",
                "step": idx + 1,
                "tactic": tactic,
                "technique": technique,
                "label": label,
                "process": ev.get("process", ""),
                "severity": ev.get("severity", "MEDIUM"),
                "timestamp": ev.get("timestamp", ""),
                "evidence": ev.get("metadata", {})
            })
        return nodes

    def to_json(self) -> dict[str, Any]:
        """
        Returns a structured graph payload with nodes and directed links.
        """
        links = []
        for i in range(len(self.nodes) - 1):
            links.append({
                "source": self.nodes[i]["id"],
                "target": self.nodes[i+1]["id"],
                "relation": "leads_to"
            })

        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "workload": f"{self.namespace}/{self.pod}",
            "node_count": len(self.nodes),
            "nodes": self.nodes,
            "edges": links
        }

    def to_mermaid(self) -> str:
        """
        Generates Mermaid flowchart diagram for markdown documentation and pull requests.
        """
        lines = [
            "```mermaid",
            "flowchart TD",
            f"    subgraph Incident[\"ThreatGuard Incident {self.incident_id}: {self.title}\"]"
        ]

        # Severity style classes
        lines.append("    classDef crit fill:#dc2626,stroke:#ef4444,stroke-width:2px,color:#ffffff,font-weight:bold;")
        lines.append("    classDef high fill:#ea580c,stroke:#f97316,stroke-width:2px,color:#ffffff,font-weight:bold;")
        lines.append("    classDef med fill:#d97706,stroke:#f59e0b,stroke-width:2px,color:#ffffff;")
        lines.append("    classDef low fill:#2563eb,stroke:#3b82f6,stroke-width:2px,color:#ffffff;")

        for n in self.nodes:
            nid = n["id"].replace("-", "_")
            step = n["step"]
            tactic = n["tactic"]
            tech = n["technique"]
            label = n["label"].replace('"', "'")
            proc = f"<br/>proc: {n['process']}" if n['process'] else ""
            lines.append(f'        {nid}["Step {step}: {tactic}<br/><b>[{tech}]</b><br/>{label}{proc}"]')

            sev = str(n.get("severity", "MED")).upper()
            if "CRIT" in sev:
                lines.append(f"        class {nid} crit;")
            elif "HIGH" in sev:
                lines.append(f"        class {nid} high;")
            elif "MED" in sev:
                lines.append(f"        class {nid} med;")
            else:
                lines.append(f"        class {nid} low;")

        # Connect nodes sequentially
        for i in range(len(self.nodes) - 1):
            s_id = self.nodes[i]["id"].replace("-", "_")
            t_id = self.nodes[i+1]["id"].replace("-", "_")
            lines.append(f"        {s_id} -->|leads to| {t_id}")

        lines.append("    end")
        lines.append("```")
        return "\n".join(lines)

    def to_ascii(self) -> str:
        """
        Renders a clean ASCII/Unicode terminal graph for CLI output and terminal investigations.
        """
        if not self.nodes:
            return f"┌── [ {self.incident_id} ] (No attack steps recorded) ──┐"

        lines = [
            "╔══════════════════════════════════════════════════════════════════════════════════╗",
            f"║ ThreatGuard Attack Chain: {self.incident_id:<15} Workload: {self.namespace}/{self.pod:<18} ║",
            f"║ Overall Severity: {self.severity:<10} Total Steps: {len(self.nodes):<33} ║",
            "╚══════════════════════════════════════════════════════════════════════════════════╝"
        ]

        for idx, n in enumerate(self.nodes):
            sev_badge = f"[{n['severity']}]"
            step_header = f"Step {n['step']}: {n['tactic']} ({n['technique']}) {sev_badge}"
            lines.append(f"  ┌── {step_header}")
            lines.append(f"  │   Action:  {n['label']}")
            if n["process"]:
                lines.append(f"  │   Process: {n['process']}")
            if n.get("timestamp"):
                lines.append(f"  │   Time:    {n['timestamp']}")
            lines.append("  └──")

            if idx < len(self.nodes) - 1:
                lines.append("        │")
                lines.append("        ▼  (escalates to)")

        return "\n".join(lines)

    def to_html_snippet(self) -> str:
        """
        Renders an embeddable HTML/CSS visual component for the web dashboard.
        """
        cards = []
        for idx, n in enumerate(self.nodes):
            sev = n.get("severity", "MEDIUM").upper()
            color_map = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#f59e0b",
                "LOW": "#3b82f6",
                "INFO": "#64748b"
            }
            border_color = color_map.get(sev, "#f59e0b")
            arrow = '<div style="display:flex;align-items:center;justify-content:center;color:#94a3b8;font-size:24px;margin:0 12px;">➔</div>' if idx < len(self.nodes) - 1 else ''

            cards.append(f"""
            <div style="flex:1;min-width:220px;background:#1e293b;border-left:4px solid {border_color};border-radius:6px;padding:14px;box-shadow:0 4px 6px -1px rgba(0,0,0,0.3);">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <span style="font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;">Step {n['step']} • {html.escape(n['tactic'])}</span>
                    <span style="background:{border_color};color:#fff;font-size:10px;font-weight:bold;padding:2px 6px;border-radius:4px;">{sev}</span>
                </div>
                <div style="font-size:14px;font-weight:600;color:#f8fafc;margin-bottom:4px;">{html.escape(n['technique'])}</div>
                <div style="font-size:12px;color:#cbd5e1;line-height:1.4;">{html.escape(n['label'])}</div>
                {f'<div style="margin-top:8px;font-size:11px;font-family:monospace;color:#38bdf8;background:#0f172a;padding:4px 6px;border-radius:4px;">{html.escape(n["process"])}</div>' if n['process'] else ''}
            </div>
            {arrow}
            """)

        return f"""
        <div style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:20px;font-family:system-ui,-apple-system,sans-serif;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
                <h4 style="margin:0;color:#f8fafc;font-size:16px;display:flex;align-items:center;gap:8px;">
                    <span style="color:#ef4444;">🛡️</span> Attack Chain: {html.escape(self.incident_id)}
                </h4>
                <span style="color:#94a3b8;font-size:12px;">Target Workload: <code style="color:#a5f3fc;">{html.escape(self.namespace)}/{html.escape(self.pod)}</code></span>
            </div>
            <div style="display:flex;flex-wrap:wrap;align-items:stretch;gap:8px;">
                {''.join(cards)}
            </div>
        </div>
        """
