"""
Attack pattern definitions mapped to MITRE ATT&CK framework.
"""

# MITRE ATT&CK Technique Mappings
MITRE_TECHNIQUES = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/"
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    "T1136": {
        "id": "T1136",
        "name": "Create Account",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1136/"
    },
    "T1548": {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation, Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1548/"
    },
    "T1041": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1041/"
    },
    "T1567": {
        "id": "T1567",
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1567/"
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/"
    },
    "T1003": {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1003/"
    },
    "T1560": {
        "id": "T1560",
        "name": "Archive Collected Data",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1560/"
    },
}


# Attack Pattern Definitions
ATTACK_PATTERNS = [
    {
        "name": "Brute Force to Compromise",
        "description": "Multiple failed login attempts followed by a successful login, indicating credential guessing attack succeeded.",
        "mitre_ids": ["T1110", "T1078"],
        "severity": "HIGH",
        "sequence": [
            {"event_type": "failed_login", "min_count": 3, "description": "3+ failed logins"},
            {"event_type": "successful_login", "within_minutes": 15, "description": "Successful login within 15 mins"},
        ],
        "iocs": ["source_ip", "target_host"],
    },
    {
        "name": "Privilege Escalation Chain",
        "description": "Successful login followed by account creation and privilege escalation, indicating attacker establishing persistence.",
        "mitre_ids": ["T1078", "T1136", "T1548"],
        "severity": "CRITICAL",
        "sequence": [
            {"event_type": "successful_login", "description": "Initial access"},
            {"event_type": "user_created", "within_minutes": 10, "description": "New account created"},
            {"event_type": "privilege_change", "within_minutes": 15, "description": "Privileges escalated"},
        ],
        "iocs": ["target_host", "username"],
    },
    {
        "name": "Data Exfiltration Pattern",
        "description": "Large file access followed by outbound data transfer, indicating potential data theft.",
        "mitre_ids": ["T1560", "T1041"],
        "severity": "CRITICAL",
        "sequence": [
            {"event_type": "file_access", "min_count": 2, "description": "Multiple file accesses"},
            {"event_type": "outbound_transfer", "within_minutes": 30, "description": "Outbound data transfer"},
        ],
        "iocs": ["target_host", "source_ip"],
    },
    {
        "name": "Reconnaissance to Attack",
        "description": "Port scanning followed by login attempts, indicating targeted attack.",
        "mitre_ids": ["T1046", "T1110"],
        "severity": "MEDIUM",
        "sequence": [
            {"event_type": "port_scan", "description": "Port scanning activity"},
            {"event_type": "failed_login", "within_minutes": 60, "min_count": 1, "description": "Login attempt after scan"},
        ],
        "iocs": ["source_ip"],
    },
    {
        "name": "Credential Harvesting",
        "description": "Access to sensitive credential files like /etc/shadow, indicating credential theft.",
        "mitre_ids": ["T1003"],
        "severity": "CRITICAL",
        "sequence": [
            {"event_type": "file_access", "file_pattern": "shadow|passwd|credentials", "description": "Sensitive file access"},
        ],
        "iocs": ["target_host", "username"],
    },
    {
        "name": "Full Attack Chain (APT)",
        "description": "Complete attack lifecycle: brute force -> access -> persistence -> escalation -> collection -> exfiltration.",
        "mitre_ids": ["T1110", "T1078", "T1136", "T1548", "T1560", "T1041"],
        "severity": "CRITICAL",
        "sequence": [
            {"event_type": "failed_login", "min_count": 3, "description": "Initial brute force"},
            {"event_type": "successful_login", "within_minutes": 15, "description": "Access gained"},
            {"event_type": "user_created", "within_minutes": 30, "description": "Persistence established"},
            {"event_type": "privilege_change", "within_minutes": 45, "description": "Privileges escalated"},
            {"event_type": "file_access", "within_minutes": 60, "description": "Data collected"},
            {"event_type": "outbound_transfer", "within_minutes": 120, "description": "Data exfiltrated"},
        ],
        "iocs": ["source_ip", "target_host"],
    },
]


def get_mitre_technique(technique_id: str) -> dict:
    """Get MITRE technique details by ID, formatted for MITRETechnique model."""
    tech = MITRE_TECHNIQUES.get(technique_id, {
        "id": technique_id,
        "name": "Unknown Technique",
        "tactic": "Unknown",
        "url": f"https://attack.mitre.org/techniques/{technique_id}/"
    })
    # Return with 'technique_id' key to match Pydantic model
    return {
        "technique_id": tech["id"],
        "name": tech["name"],
        "tactic": tech["tactic"],
        "url": tech["url"]
    }


def get_pattern_by_name(name: str) -> dict | None:
    """Get attack pattern by name."""
    for pattern in ATTACK_PATTERNS:
        if pattern["name"] == name:
            return pattern
    return None
