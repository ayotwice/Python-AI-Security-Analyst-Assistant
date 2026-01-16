"""
Report Generator - Creates beautiful console output.
"""

from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich import box

from .models import AnalysisResult, Incident, Severity


# Severity color mapping
SEVERITY_COLORS = {
    "CRITICAL": "red bold",
    "HIGH": "orange1",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim"
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪"
}


class ReportGenerator:
    """
    Generates beautiful console reports from analysis results.

    """
    
    def __init__(self):
        self.console = Console()
    
    def generate(self, result: AnalysisResult) -> None:
        """
        Generate and print the full security analysis report.
        
        Args:
            result: The AnalysisResult to report on
        """
        self._print_header(result)
        self._print_executive_summary(result)
        self._print_threat_summary(result)
        self._print_incidents(result)
        self._print_mitre_mapping(result)
        self._print_recommendations(result)
        self._print_footer(result)
    
    def _print_header(self, result: AnalysisResult) -> None:
        """Print the report header."""
        header = Text()
        header.append("🛡️ SECURITY ANALYSIS REPORT\n", style="bold white on blue")
        header.append(f"Generated: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}\n", style="dim")
        header.append(f"Analysis ID: {result.analysis_id}", style="dim")
        
        self.console.print(Panel(
            header,
            title="[bold blue]Bespin Security Analyst[/bold blue]",
            subtitle="[dim]Powered by AI[/dim]",
            box=box.DOUBLE_EDGE
        ))
        self.console.print()
    
    def _print_executive_summary(self, result: AnalysisResult) -> None:
        """Print the executive summary section."""
        # Count incidents by severity
        severity_counts = {}
        for incident in result.incidents:
            sev = incident.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Determine overall threat level
        if severity_counts.get(Severity.CRITICAL, 0) > 0:
            threat_level = "CRITICAL"
            threat_color = "red bold"
        elif severity_counts.get(Severity.HIGH, 0) > 0:
            threat_level = "HIGH"
            threat_color = "orange1"
        elif severity_counts.get(Severity.MEDIUM, 0) > 0:
            threat_level = "MEDIUM"
            threat_color = "yellow"
        else:
            threat_level = "LOW"
            threat_color = "green"
        
        summary_content = Text()
        summary_content.append("THREAT LEVEL: ", style="bold")
        summary_content.append(f"{threat_level}\n\n", style=threat_color)
        
        if result.executive_summary:
            summary_content.append(result.executive_summary)
        else:
            summary_content.append(f"Analyzed {result.total_events_analyzed} security events ")
            summary_content.append(f"and {result.total_vulnerabilities} vulnerabilities. ")
            summary_content.append(f"Detected {len(result.incidents)} potential incidents.")
        
        self.console.print(Panel(
            summary_content,
            title="[bold]📋 Executive Summary[/bold]",
            border_style="blue"
        ))
        self.console.print()
    
    def _print_threat_summary(self, result: AnalysisResult) -> None:
        """Print a summary table of threats."""
        table = Table(
            title="📊 Analysis Overview",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan"
        )
        
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")
        table.add_column("Status", justify="center")
        
        # Events analyzed
        table.add_row(
            "Events Analyzed",
            str(result.total_events_analyzed),
            "✅"
        )
        
        # Vulnerabilities
        vuln_status = "⚠️" if result.total_vulnerabilities > 0 else "✅"
        table.add_row(
            "Vulnerabilities Found",
            str(result.total_vulnerabilities),
            vuln_status
        )
        
        # Incidents by severity
        critical = sum(1 for i in result.incidents if i.severity == Severity.CRITICAL)
        high = sum(1 for i in result.incidents if i.severity == Severity.HIGH)
        medium = sum(1 for i in result.incidents if i.severity == Severity.MEDIUM)
        
        if critical > 0:
            table.add_row(
                "🔴 Critical Incidents",
                str(critical),
                "[red bold]ALERT[/red bold]"
            )
        if high > 0:
            table.add_row(
                "🟠 High Incidents",
                str(high),
                "[orange1]WARNING[/orange1]"
            )
        if medium > 0:
            table.add_row(
                "🟡 Medium Incidents",
                str(medium),
                "[yellow]REVIEW[/yellow]"
            )
        
        self.console.print(table)
        self.console.print()
    
    def _print_incidents(self, result: AnalysisResult) -> None:
        """Print detailed incident information."""
        if not result.incidents:
            self.console.print(Panel(
                "[green]No significant incidents detected.[/green]",
                title="🎯 Detected Incidents",
                border_style="green"
            ))
            return
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        sorted_incidents = sorted(
            result.incidents, 
            key=lambda i: severity_order.get(i.severity, 5)
        )
        
        self.console.print("[bold]🎯 Detected Incidents[/bold]")
        self.console.print()
        
        for incident in sorted_incidents:
            self._print_incident_detail(incident)
    
    def _print_incident_detail(self, incident: Incident) -> None:
        """Print details for a single incident."""
        sev = incident.severity
        icon = SEVERITY_ICONS.get(sev, "⚪")
        color = SEVERITY_COLORS.get(sev, "white")
        
        # Build incident content
        content = Text()
        content.append(f"Severity: ", style="bold")
        content.append(f"{sev}\n", style=color)
        
        content.append(f"Confidence: ", style="bold")
        content.append(f"{incident.confidence:.0%}\n\n", style="dim")
        
        content.append(incident.description)
        content.append("\n")
        
        # Affected entities
        if incident.affected_entities:
            content.append("\n📍 Affected Entities:\n", style="bold")
            for entity in incident.affected_entities[:5]:
                content.append(f"   • {entity}\n")
        
        # MITRE techniques
        if incident.mitre_techniques:
            content.append("\n🎯 MITRE ATT&CK:\n", style="bold")
            for tech in incident.mitre_techniques[:3]:
                content.append(f"   • {tech.technique_id}: {tech.name} ({tech.tactic})\n", style="cyan")
        
        # Recommendations
        if incident.recommendations:
            content.append("\n💡 Recommendations:\n", style="bold")
            for rec in incident.recommendations[:3]:
                content.append(f"   • {rec}\n")
        
        self.console.print(Panel(
            content,
            title=f"[{color}]{icon} {incident.title}[/{color}]",
            border_style=color.split()[0] if " " in color else color
        ))
        self.console.print()
    
    def _print_mitre_mapping(self, result: AnalysisResult) -> None:
        """Print MITRE ATT&CK technique mapping."""
        # Collect all unique techniques
        all_techniques = {}
        for incident in result.incidents:
            for tech in incident.mitre_techniques:
                all_techniques[tech.technique_id] = tech
        
        if not all_techniques:
            return
        
        tree = Tree("[bold cyan]🎯 MITRE ATT&CK Mapping[/bold cyan]")
        
        # Group by tactic
        tactics = {}
        for tech in all_techniques.values():
            tactic = tech.tactic.split(",")[0].strip()  # Take first tactic
            if tactic not in tactics:
                tactics[tactic] = []
            tactics[tactic].append(tech)
        
        for tactic, techniques in tactics.items():
            tactic_branch = tree.add(f"[bold]{tactic}[/bold]")
            for tech in techniques:
                tactic_branch.add(f"[cyan]{tech.technique_id}[/cyan]: {tech.name}")
        
        self.console.print(tree)
        self.console.print()
    
    def _print_recommendations(self, result: AnalysisResult) -> None:
        """Print prioritized recommendations."""
        if not result.recommendations:
            return
        
        table = Table(
            title="💡 Prioritized Recommendations",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold green"
        )
        
        table.add_column("#", style="bold", width=4)
        table.add_column("Priority", justify="center", width=12)
        table.add_column("Action", style="white")
        
        for i, rec in enumerate(result.recommendations, 1):
            # Parse priority from recommendation
            if rec.startswith("[IMMEDIATE]"):
                priority = "[red bold]IMMEDIATE[/red bold]"
                action = rec.replace("[IMMEDIATE]", "").strip()
            elif rec.startswith("[URGENT]"):
                priority = "[orange1 bold]URGENT[/orange1 bold]"
                action = rec.replace("[URGENT]", "").strip()
            elif rec.startswith("[IMPORTANT]"):
                priority = "[yellow]IMPORTANT[/yellow]"
                action = rec.replace("[IMPORTANT]", "").strip()
            elif rec.startswith("[ONGOING]"):
                priority = "[blue]ONGOING[/blue]"
                action = rec.replace("[ONGOING]", "").strip()
            else:
                priority = "[dim]TBD[/dim]"
                action = rec
            
            table.add_row(str(i), priority, action)
        
        self.console.print(table)
        self.console.print()
    
    def _print_footer(self, result: AnalysisResult) -> None:
        """Print the report footer."""
        # Attack narrative if available
        if result.detailed_findings:
            self.console.print(Panel(
                result.detailed_findings,
                title="[bold]📖 Attack Narrative[/bold]",
                border_style="magenta"
            ))
            self.console.print()
        
        footer = Text()
        footer.append("Analysis complete. ", style="bold green")
        footer.append("Please review findings and take recommended actions.\n", style="dim")
        footer.append("For questions, contact your security team.", style="dim")
        
        self.console.print(Panel(
            footer,
            title="[dim]End of Report[/dim]",
            border_style="dim"
        ))


def print_simple_report(result: AnalysisResult) -> None:
    """
    Print a simple text-based report (no Rich formatting).
    Useful for piping to files or non-terminal environments.
    """
    print("=" * 70)
    print("           SECURITY ANALYSIS REPORT")
    print(f"           Generated: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print()
    
    print("EXECUTIVE SUMMARY")
    print("-" * 40)
    print(f"Events Analyzed: {result.total_events_analyzed}")
    print(f"Vulnerabilities: {result.total_vulnerabilities}")
    print(f"Incidents Found: {len(result.incidents)}")
    print()
    
    if result.executive_summary:
        print(result.executive_summary)
        print()
    
    print("DETECTED INCIDENTS")
    print("-" * 40)
    for incident in result.incidents:
        print(f"[{incident.severity}] {incident.title}")
        print(f"  {incident.description}")
        print()
    
    print("RECOMMENDATIONS")
    print("-" * 40)
    for i, rec in enumerate(result.recommendations, 1):
        print(f"{i}. {rec}")
    
    print()
    print("=" * 70)
    print("                   END OF REPORT")
    print("=" * 70)
