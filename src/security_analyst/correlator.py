"""
Correlation Engine - Connects related security events to reveal attack patterns.
"""

import uuid
from datetime import timedelta
from collections import defaultdict
from typing import Optional

from .models import SecurityEvent, CorrelatedGroup, Incident, MITRETechnique, Severity
from .patterns import ATTACK_PATTERNS, get_mitre_technique


class TimeWindowCorrelator:
    """
    Groups events that occur within a time window.
    """
    
    def correlate(
        self, 
        events: list[SecurityEvent], 
        window: timedelta = timedelta(minutes=5)
    ) -> list[list[SecurityEvent]]:
        """
        Group events by time proximity.
        
        Args:
            events: List of security events to cluster
            window: Time window for grouping (default: 5 minutes)
            
        Returns:
            List of event clusters
        """
        if not events:
            return []
        
        # Sort by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        clusters = []
        current_cluster = [sorted_events[0]]
        
        for event in sorted_events[1:]:
            # Check if event is within window of cluster start
            if event.timestamp - current_cluster[0].timestamp <= window:
                current_cluster.append(event)
            else:
                # Start new cluster
                if current_cluster:
                    clusters.append(current_cluster)
                current_cluster = [event]
        
        # Don't forget the last cluster
        if current_cluster:
            clusters.append(current_cluster)
        
        return clusters


class EntityCorrelator:
    """
    Links events that share common entities (IP, user, host).
    """
    
    def correlate(self, events: list[SecurityEvent]) -> dict[str, list[SecurityEvent]]:
        """
        Group events by shared entities.
        
        Args:
            events: List of security events
            
        Returns:
            Dictionary mapping entity identifiers to related events
        """
        entity_map = defaultdict(list)
        
        for event in events:
            # Group by source IP
            if event.source_ip:
                entity_map[f"ip:{event.source_ip}"].append(event)
            
            # Group by target host
            if event.target_host:
                entity_map[f"host:{event.target_host}"].append(event)
            
            # Group by username
            if event.username:
                entity_map[f"user:{event.username}"].append(event)
        
        return dict(entity_map)


class PatternCorrelator:
    """
    Matches event sequences against known attack patterns.
    """
    
    def __init__(self):
        self.patterns = ATTACK_PATTERNS
    
    def match_patterns(
        self, 
        events: list[SecurityEvent]
    ) -> list[tuple[dict, list[SecurityEvent], float]]:
        """
        Find attack patterns in event sequences.
        
        Args:
            events: List of events to analyze
            
        Returns:
            List of (pattern, matching_events, confidence) tuples
        """
        matches = []
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        for pattern in self.patterns:
            match_result = self._check_pattern(sorted_events, pattern)
            if match_result:
                matched_events, confidence = match_result
                matches.append((pattern, matched_events, confidence))
        
        return matches
    
    def _check_pattern(
        self, 
        events: list[SecurityEvent], 
        pattern: dict
    ) -> Optional[tuple[list[SecurityEvent], float]]:
        """Check if events match a specific pattern."""
        sequence = pattern["sequence"]
        matched_events = []
        last_match_time = None
        confidence = 1.0
        
        for step in sequence:
            step_matched = False
            required_type = step["event_type"]
            min_count = step.get("min_count", 1)
            within_minutes = step.get("within_minutes")
            
            # Find matching events
            step_matches = []
            for event in events:
                if event.event_type == required_type:
                    # Check time constraint if set
                    if within_minutes and last_match_time:
                        time_diff = (event.timestamp - last_match_time).total_seconds() / 60
                        if time_diff > within_minutes:
                            continue
                    
                    step_matches.append(event)
            
            if len(step_matches) >= min_count:
                matched_events.extend(step_matches[:min_count])
                last_match_time = step_matches[0].timestamp
                step_matched = True
            
            if not step_matched:
                return None
        
        # Calculate confidence based on pattern completeness
        confidence = min(1.0, len(matched_events) / len(sequence))
        
        return matched_events, confidence


class CorrelationEngine:
    
    def __init__(self):
        self.time_correlator = TimeWindowCorrelator()
        self.entity_correlator = EntityCorrelator()
        self.pattern_correlator = PatternCorrelator()
    
    def analyze(
        self, 
        events: list[SecurityEvent],
        time_window: timedelta = timedelta(minutes=10)
    ) -> tuple[list[CorrelatedGroup], list[Incident]]:
        """
        Run full correlation analysis on events.
        
        Args:
            events: List of security events to analyze
            time_window: Time window for clustering
            
        Returns:
            Tuple of (correlated_groups, detected_incidents)
        """
        correlated_groups = []
        incidents = []
        
        # Step 1: Group events by time
        time_clusters = self.time_correlator.correlate(events, time_window)
        
        for cluster in time_clusters:
            # Step 2: Group by entities within time cluster
            entity_groups = self.entity_correlator.correlate(cluster)
            
            for entity_key, related_events in entity_groups.items():
                if len(related_events) > 1:  # Only interesting if multiple events
                    # Create correlated group
                    group = CorrelatedGroup(
                        id=f"grp-{uuid.uuid4().hex[:8]}",
                        events=related_events,
                        correlation_type="entity",
                        correlation_reason=f"Events related to {entity_key}",
                        confidence=0.8
                    )
                    correlated_groups.append(group)
                
                # Step 3: Check for attack patterns
                pattern_matches = self.pattern_correlator.match_patterns(related_events)
                
                for pattern, matched_events, confidence in pattern_matches:
                    # Build MITRE technique list
                    mitre_techniques = [
                        MITRETechnique(**get_mitre_technique(tid))
                        for tid in pattern.get("mitre_ids", [])
                    ]
                    
                    # Get affected entities
                    affected = set()
                    for event in matched_events:
                        if event.source_ip:
                            affected.add(f"IP: {event.source_ip}")
                        if event.target_host:
                            affected.add(f"Host: {event.target_host}")
                        if event.username:
                            affected.add(f"User: {event.username}")
                    
                    # Build timeline
                    timeline = [
                        {
                            "time": e.timestamp.isoformat(),
                            "type": e.event_type,
                            "description": f"{e.action or e.event_type} on {e.target_host or 'unknown'}"
                        }
                        for e in sorted(matched_events, key=lambda x: x.timestamp)
                    ]
                    
                    # Create incident
                    incident = Incident(
                        id=f"inc-{uuid.uuid4().hex[:8]}",
                        title=pattern["name"],
                        severity=Severity(pattern["severity"]),
                        description=pattern["description"],
                        events=matched_events,
                        mitre_techniques=mitre_techniques,
                        affected_entities=list(affected),
                        timeline=timeline,
                        recommendations=self._generate_recommendations(pattern, matched_events),
                        confidence=confidence
                    )
                    incidents.append(incident)
        
        # Deduplicate incidents (same pattern might match multiple entity groups)
        unique_incidents = self._deduplicate_incidents(incidents)
        
        return correlated_groups, unique_incidents
    
    def _generate_recommendations(
        self, 
        pattern: dict, 
        events: list[SecurityEvent]
    ) -> list[str]:
        """Generate actionable recommendations based on pattern type."""
        recommendations = []
        
        # Get unique entities for specific recommendations
        ips = set(e.source_ip for e in events if e.source_ip)
        hosts = set(e.target_host for e in events if e.target_host)
        users = set(e.username for e in events if e.username)
        
        pattern_name = pattern["name"]
        
        if "Brute Force" in pattern_name:
            for ip in ips:
                recommendations.append(f"[IMMEDIATE] Block IP {ip} at firewall/WAF")
            recommendations.append("[URGENT] Review and rotate compromised credentials")
            recommendations.append("[24 HOURS] Implement account lockout policies")
            
        elif "Privilege Escalation" in pattern_name:
            for user in users:
                recommendations.append(f"[IMMEDIATE] Disable user account: {user}")
            for host in hosts:
                recommendations.append(f"[URGENT] Isolate host {host} for forensic analysis")
            recommendations.append("[24 HOURS] Audit all recent account creations")
            
        elif "Exfiltration" in pattern_name:
            for host in hosts:
                recommendations.append(f"[IMMEDIATE] Isolate {host} from network")
            recommendations.append("[URGENT] Identify all data that was accessed")
            recommendations.append("[24 HOURS] Legal/compliance notification assessment")
            
        elif "Reconnaissance" in pattern_name:
            for ip in ips:
                recommendations.append(f"[IMPORTANT] Monitor traffic from {ip}")
            recommendations.append("[24 HOURS] Review exposed services and patch vulnerabilities")
            
        else:
            recommendations.append("[URGENT] Investigate affected systems")
            recommendations.append("[24 HOURS] Review security controls")
        
        return recommendations
    
    def _deduplicate_incidents(
        self, 
        incidents: list[Incident]
    ) -> list[Incident]:
        """Remove duplicate incidents based on pattern and entities."""
        seen = set()
        unique = []
        
        for incident in incidents:
            # Create a key based on pattern and affected entities
            key = (incident.title, tuple(sorted(incident.affected_entities)))
            if key not in seen:
                seen.add(key)
                unique.append(incident)
        
        return unique
