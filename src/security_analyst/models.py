"""
Data models for the Security Analyst tool.
Using Pydantic for type safety and validation.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for security events and incidents."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EventType(str, Enum):
    """Types of security events we can analyze."""
    FAILED_LOGIN = "failed_login"
    SUCCESSFUL_LOGIN = "successful_login"
    USER_CREATED = "user_created"
    PRIVILEGE_CHANGE = "privilege_change"
    FILE_ACCESS = "file_access"
    OUTBOUND_TRANSFER = "outbound_transfer"
    PORT_SCAN = "port_scan"
    MALWARE_DETECTED = "malware_detected"
    POLICY_VIOLATION = "policy_violation"
    VULNERABILITY = "vulnerability"
    UNKNOWN = "unknown"


class SecurityEvent(BaseModel):
    """
    A single security event from logs/SIEM.

    """
    id: str = Field(description="Unique identifier for this event")
    timestamp: datetime = Field(description="When the event occurred")
    event_type: EventType = Field(description="Category of the event")
    source_ip: Optional[str] = Field(default=None, description="IP address that initiated the action")
    target_host: Optional[str] = Field(default=None, description="Host that was targeted")
    target_port: Optional[int] = Field(default=None, description="Port that was targeted")
    username: Optional[str] = Field(default=None, description="User involved in the event")
    action: Optional[str] = Field(default=None, description="What action was taken")
    outcome: Optional[str] = Field(default=None, description="success, failure, blocked, etc.")
    details: dict = Field(default_factory=dict, description="Additional event details")
    raw_log: Optional[str] = Field(default=None, description="Original log line if available")

    class Config:
        use_enum_values = True


class Vulnerability(BaseModel):
    """
    A vulnerability finding from a security scan.

    """
    id: str = Field(description="Unique identifier")
    cve_id: Optional[str] = Field(default=None, description="CVE identifier if available")
    title: str = Field(description="Short description of the vulnerability")
    description: str = Field(description="Detailed description")
    severity: Severity = Field(description="How bad is this?")
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0, description="CVSS score 0-10")
    affected_host: str = Field(description="Host where this was found")
    affected_software: Optional[str] = Field(default=None, description="Vulnerable software")
    remediation: Optional[str] = Field(default=None, description="How to fix it")
    
    class Config:
        use_enum_values = True


class MITRETechnique(BaseModel):
    """Reference to a MITRE ATT&CK technique."""
    technique_id: str = Field(description="e.g., T1110")
    name: str = Field(description="e.g., Brute Force")
    tactic: str = Field(description="e.g., Credential Access")
    url: str = Field(default="", description="Link to MITRE page")


class CorrelatedGroup(BaseModel):
    """
    A group of events that are related to each other.

    """
    id: str = Field(description="Unique identifier for this group")
    events: list[SecurityEvent] = Field(description="Events in this group")
    correlation_type: str = Field(description="time, entity, pattern, or ai")
    correlation_reason: str = Field(description="Why these events are grouped")
    confidence: float = Field(ge=0.0, le=1.0, description="How confident we are (0-1)")


class Incident(BaseModel):
    """
    A security incident - a confirmed or suspected attack.
    """
    id: str = Field(description="Unique identifier")
    title: str = Field(description="Short description of the incident")
    severity: Severity = Field(description="How critical is this?")
    description: str = Field(description="What happened")
    events: list[SecurityEvent] = Field(description="Events that make up this incident")
    mitre_techniques: list[MITRETechnique] = Field(default_factory=list, description="MITRE ATT&CK mappings")
    affected_entities: list[str] = Field(default_factory=list, description="IPs, users, hosts involved")
    timeline: list[dict] = Field(default_factory=list, description="Chronological event summary")
    recommendations: list[str] = Field(default_factory=list, description="What to do about it")
    confidence: float = Field(ge=0.0, le=1.0, description="How confident we are (0-1)")
    
    class Config:
        use_enum_values = True


class AnalysisResult(BaseModel):
    """
    The complete result of analyzing security artifacts.
    """
    analysis_id: str = Field(description="Unique identifier for this analysis")
    timestamp: datetime = Field(default_factory=datetime.now, description="When analysis was performed")
    total_events_analyzed: int = Field(description="How many events we looked at")
    total_vulnerabilities: int = Field(default=0, description="How many vulns found")
    incidents: list[Incident] = Field(default_factory=list, description="Detected incidents")
    correlated_groups: list[CorrelatedGroup] = Field(default_factory=list, description="Related event groups")
    executive_summary: str = Field(default="", description="High-level summary for leadership")
    detailed_findings: str = Field(default="", description="Detailed technical analysis")
    recommendations: list[str] = Field(default_factory=list, description="Prioritized action items")
    raw_ai_response: Optional[str] = Field(default=None, description="Raw LLM output for debugging")
