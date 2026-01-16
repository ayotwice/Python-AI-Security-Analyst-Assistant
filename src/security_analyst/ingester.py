"""
Artifact Ingester - Loads and parses security artifacts.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Union

from .models import SecurityEvent, Vulnerability, EventType, Severity


class ArtifactIngester:
    """
    Loads security artifacts from various formats and normalizes them
    into our standard data models.
    """

    def load_siem_logs(self, path: Union[str, Path]) -> list[SecurityEvent]:
        """
        Load SIEM/security logs from a JSON file.
        
        Args:
            path: Path to the JSON file containing security events
            
        Returns:
            List of SecurityEvent objects
        """
        path = Path(path)
        
        if not path.exists():
            raise FileNotFoundError(f"SIEM log file not found: {path}")
        
        with open(path, 'r') as f:
            raw_logs = json.load(f)
        
        events = []
        for log in raw_logs:
            # Parse timestamp
            if isinstance(log.get('timestamp'), str):
                log['timestamp'] = datetime.fromisoformat(
                    log['timestamp'].replace('Z', '+00:00')
                )
            
            # Map event type string to enum
            event_type_str = log.get('event_type', 'unknown')
            try:
                log['event_type'] = EventType(event_type_str)
            except ValueError:
                log['event_type'] = EventType.UNKNOWN
            
            events.append(SecurityEvent(**log))
        
        return events

    def load_vulnerability_scan(self, path: Union[str, Path]) -> list[Vulnerability]:
        """
        Load vulnerability scan results from a JSON file.
        
        Args:
            path: Path to the JSON file containing vulnerability findings
            
        Returns:
            List of Vulnerability objects
        """
        path = Path(path)
        
        if not path.exists():
            raise FileNotFoundError(f"Vulnerability scan file not found: {path}")
        
        with open(path, 'r') as f:
            raw_vulns = json.load(f)
        
        vulnerabilities = []
        for vuln in raw_vulns:
            # Map severity string to enum
            severity_str = vuln.get('severity', 'INFO')
            try:
                vuln['severity'] = Severity(severity_str)
            except ValueError:
                vuln['severity'] = Severity.INFO
            
            vulnerabilities.append(Vulnerability(**vuln))
        
        return vulnerabilities

    def load_from_directory(self, directory: Union[str, Path]) -> tuple[list[SecurityEvent], list[Vulnerability]]:
        """
        Load all supported artifacts from a directory.
        
        Args:
            directory: Path to directory containing artifact files
            
        Returns:
            Tuple of (events, vulnerabilities)
        """
        directory = Path(directory)
        
        all_events = []
        all_vulns = []
        
        # Look for SIEM logs
        for log_file in directory.glob("**/siem*.json"):
            print(f"  📄 Loading SIEM logs from: {log_file.name}")
            all_events.extend(self.load_siem_logs(log_file))
        
        for log_file in directory.glob("**/*_logs.json"):
            if "siem" not in log_file.name:  # Avoid duplicates
                print(f"  📄 Loading logs from: {log_file.name}")
                all_events.extend(self.load_siem_logs(log_file))
        
        # Look for vulnerability scans
        for vuln_file in directory.glob("**/vuln*.json"):
            print(f"  🔍 Loading vulnerability scan from: {vuln_file.name}")
            all_vulns.extend(self.load_vulnerability_scan(vuln_file))
        
        return all_events, all_vulns

    def get_summary(self, events: list[SecurityEvent], vulns: list[Vulnerability]) -> dict:
        """
        Get a quick summary of loaded artifacts.
        
        Returns:
            Dictionary with counts and key statistics
        """
        # Count events by type
        event_counts = {}
        for event in events:
            event_type = event.event_type
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
        
        # Count vulns by severity
        vuln_severity = {}
        for vuln in vulns:
            severity = vuln.severity
            vuln_severity[severity] = vuln_severity.get(severity, 0) + 1
        
        # Get unique entities
        unique_ips = set()
        unique_hosts = set()
        unique_users = set()
        
        for event in events:
            if event.source_ip:
                unique_ips.add(event.source_ip)
            if event.target_host:
                unique_hosts.add(event.target_host)
            if event.username:
                unique_users.add(event.username)
        
        return {
            "total_events": len(events),
            "total_vulnerabilities": len(vulns),
            "event_types": event_counts,
            "vulnerability_severities": vuln_severity,
            "unique_source_ips": len(unique_ips),
            "unique_target_hosts": len(unique_hosts),
            "unique_users": len(unique_users),
            "time_range": {
                "earliest": min(e.timestamp for e in events).isoformat() if events else None,
                "latest": max(e.timestamp for e in events).isoformat() if events else None,
            }
        }
