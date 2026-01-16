"""
Prompt templates for the AI Security Analyst.
"""

# System prompt defining the AI's role and expertise
SYSTEM_PROMPT = """You are an expert Security Analyst on a Purple Team with 10+ years of experience in threat detection, incident response, and vulnerability assessment.

Your expertise includes:
- Recognizing attack patterns and mapping them to the MITRE ATT&CK framework
- Correlating seemingly unrelated events to identify sophisticated attacks
- Prioritizing threats by business impact and exploitability  
- Providing actionable remediation steps that balance security with operations
- Understanding attacker TTPs (Tactics, Techniques, and Procedures)

Your analysis style:
- Be thorough but concise - busy analysts need actionable insights fast
- Always explain WHY something is suspicious, not just WHAT you found
- Provide specific, implementable recommendations
- Consider both immediate containment and long-term remediation
- Highlight any gaps in the data that limit your conclusions

You communicate clearly with both technical security teams and executive leadership."""


# Main analysis prompt template
ANALYSIS_PROMPT = """## Security Artifact Analysis Request

### Context
You are analyzing security events and vulnerabilities from a client environment.
Your goal is to identify threats, assess risk, and provide actionable recommendations.

### Artifacts Provided

**Security Events Summary:**
- Total Events: {total_events}
- Time Range: {time_range}
- Unique Source IPs: {unique_ips}
- Unique Target Hosts: {unique_hosts}

**Event Type Breakdown:**
{event_breakdown}

**Pre-Correlated Incidents Detected:**
{incidents_summary}

**Vulnerabilities Found:**
- Total: {total_vulns}
- Critical: {critical_vulns}
- High: {high_vulns}

**Raw Event Data (sample):**
```json
{sample_events}
```

**Vulnerability Data:**
```json
{vulnerability_data}
```

### Analysis Tasks

1. **Threat Assessment**: Analyze the events and identify any malicious or suspicious activity. Consider:
   - Are there indicators of active attacks?
   - What is the attacker's likely objective?
   - What stage of the kill chain are they in?

2. **Vulnerability Correlation**: Connect vulnerabilities to the detected activity:
   - Could any vulnerabilities have enabled the observed attacks?
   - Which vulnerabilities pose immediate risk given the threat landscape?

3. **Attack Narrative**: If an attack is detected, construct the narrative:
   - Initial access method
   - Lateral movement
   - Persistence mechanisms
   - Data access/exfiltration

4. **Risk Prioritization**: Rank findings by severity considering:
   - Confirmed vs. suspected malicious activity
   - Business impact
   - Ease of exploitation

5. **Recommendations**: Provide specific, prioritized actions:
   - [IMMEDIATE] - Do within the hour
   - [URGENT] - Do within 24 hours  
   - [IMPORTANT] - Do within the week
   - [ONGOING] - Long-term improvements

### Response Format

Respond with a structured JSON object:
```json
{{
    "executive_summary": "2-3 sentence summary for leadership",
    "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
    "active_threats": [
        {{
            "title": "Threat name",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "description": "What's happening",
            "evidence": ["list of supporting events"],
            "mitre_techniques": ["T1110", "T1078"],
            "confidence": 0.95
        }}
    ],
    "attack_narrative": "Full story of the attack if detected",
    "vulnerability_risks": [
        {{
            "cve": "CVE-XXXX-XXXX",
            "risk_context": "Why this matters given current threats"
        }}
    ],
    "recommendations": [
        {{
            "priority": "IMMEDIATE|URGENT|IMPORTANT|ONGOING",
            "action": "Specific action to take",
            "rationale": "Why this is important"
        }}
    ],
    "gaps_and_limitations": ["What we couldn't determine from available data"],
    "additional_data_needed": ["What would help confirm findings"]
}}
```
"""


# Correlation enhancement prompt
CORRELATION_PROMPT = """## Event Correlation Analysis

You are examining a set of security events that may be related.
Your task is to find hidden connections that automated systems might miss.

### Events to Analyze:
```json
{events_json}
```

### Analysis Tasks:

1. **Find Hidden Connections**: Look for relationships that might not be obvious:
   - Same subnet or network segment
   - Similar timing patterns (regular intervals, business hours, etc.)
   - Related services or applications
   - Common user behavior patterns

2. **Identify Attack Narratives**: If these events tell a story of an attack:
   - Describe the narrative step by step
   - Identify the attacker's likely goals
   - Estimate how far the attack has progressed

3. **Rate Correlation Confidence**: How confident are you these events are related?
   - Consider: Could this be coincidence? Normal operations? 

4. **Suggest Pivots**: What additional data sources would help confirm your hypothesis?

### Response Format:
```json
{{
    "correlated_groups": [
        {{
            "event_ids": ["evt-001", "evt-002"],
            "relationship": "Description of how they're related",
            "confidence": 0.85
        }}
    ],
    "attack_narrative": "Step-by-step attack story if applicable",
    "overall_confidence": 0.85,
    "suggested_pivots": [
        "Check DNS logs for the suspicious external IP",
        "Review authentication logs for lateral movement"
    ]
}}
```
"""


# Vulnerability risk assessment prompt  
VULNERABILITY_PROMPT = """## Vulnerability Risk Assessment

Analyze these vulnerabilities in the context of the observed security events.

### Detected Security Events Summary:
{events_summary}

### Vulnerabilities to Assess:
```json
{vulnerabilities_json}
```

### Analysis Tasks:

1. **Exploitation Likelihood**: For each vulnerability, assess:
   - Could it have been exploited based on observed activity?
   - Are there signs of exploitation attempts?
   - What skill level is required to exploit?

2. **Business Impact**: Consider:
   - What systems/data could be compromised?
   - What's the blast radius if exploited?

3. **Prioritized Remediation**: Create a prioritized patch plan considering:
   - Active exploitation indicators
   - CVSS score
   - Business criticality
   - Ease of patching

### Response Format:
```json
{{
    "risk_summary": "Overall vulnerability posture",
    "exploitation_evidence": [
        {{
            "vulnerability_id": "vuln-001",
            "exploitation_status": "CONFIRMED|LIKELY|POSSIBLE|UNLIKELY",
            "evidence": ["Supporting events or indicators"]
        }}
    ],
    "prioritized_patches": [
        {{
            "rank": 1,
            "vulnerability_id": "vuln-001",
            "urgency": "IMMEDIATE|URGENT|IMPORTANT",
            "rationale": "Why this should be patched first"
        }}
    ]
}}
```
"""


def build_analysis_prompt(
    events_summary: dict,
    incidents: list,
    vulnerabilities: list,
    sample_events: str
) -> str:
    """Build the main analysis prompt with data inserted."""
    
    # Format event breakdown
    event_breakdown = "\n".join([
        f"  - {event_type}: {count}"
        for event_type, count in events_summary.get("event_types", {}).items()
    ])
    
    # Format incidents summary
    if incidents:
        incidents_summary = "\n".join([
            f"  - [{inc.severity}] {inc.title}: {len(inc.events)} events"
            for inc in incidents
        ])
    else:
        incidents_summary = "  No incidents pre-detected by correlation engine"
    
    # Count vulnerabilities by severity
    critical = sum(1 for v in vulnerabilities if v.severity == "CRITICAL")
    high = sum(1 for v in vulnerabilities if v.severity == "HIGH")
    
    # Format vulnerability data
    vuln_data = [
        {
            "id": v.id,
            "cve": v.cve_id,
            "title": v.title,
            "severity": v.severity,
            "cvss": v.cvss_score,
            "host": v.affected_host
        }
        for v in vulnerabilities[:5]  # Limit to top 5
    ]
    
    import json
    
    return ANALYSIS_PROMPT.format(
        total_events=events_summary.get("total_events", 0),
        time_range=f"{events_summary.get('time_range', {}).get('earliest', 'N/A')} to {events_summary.get('time_range', {}).get('latest', 'N/A')}",
        unique_ips=events_summary.get("unique_source_ips", 0),
        unique_hosts=events_summary.get("unique_target_hosts", 0),
        event_breakdown=event_breakdown,
        incidents_summary=incidents_summary,
        total_vulns=len(vulnerabilities),
        critical_vulns=critical,
        high_vulns=high,
        sample_events=sample_events,
        vulnerability_data=json.dumps(vuln_data, indent=2)
    )
