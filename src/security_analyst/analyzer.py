"""
AI Security Analyzer using Agno framework with OpenRouter.

Sends security data to an LLM and gets back expert analysis.
"""

import os
import json
import uuid
import logging
from datetime import datetime
from typing import Optional

# Suppress verbose logging from third-party libraries
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("openai").setLevel(logging.WARNING)
logging.getLogger("agno").setLevel(logging.WARNING)

from agno.agent import Agent
from agno.models.openrouter import OpenRouter
from dotenv import load_dotenv

from .models import (
    SecurityEvent, 
    Vulnerability, 
    AnalysisResult, 
    Incident,
    CorrelatedGroup,
    Severity,
    MITRETechnique
)
from .prompts import SYSTEM_PROMPT, build_analysis_prompt, CORRELATION_PROMPT
from .patterns import get_mitre_technique

# Load environment variables
load_dotenv()


class SecurityAnalyzer:
    """
    AI-powered security analyzer using Agno + OpenRouter.
    
    Sends security data to an LLM and gets back expert analysis.
    """
    
    def __init__(
        self, 
        model_id: str = "google/gemini-2.0-flash-001",
        api_key: Optional[str] = None
    ):
        """
        Initialize the security analyzer.
        
        Args:
            model_id: OpenRouter model to use
            api_key: Optional API key (defaults to OPENROUTER_API_KEY env var)
        """
        # Set API key if provided
        if api_key:
            os.environ["OPENROUTER_API_KEY"] = api_key
        
        # Verify API key is available
        if not os.environ.get("OPENROUTER_API_KEY"):
            raise ValueError(
                "No API key found. Set OPENROUTER_API_KEY environment variable "
                "or pass api_key parameter."
            )
        
        self.model_id = model_id
        
        # Use OpenRouter for all requests
        print(f"  🧠 Using model: {model_id}")
        model = OpenRouter(id=model_id)
            
        # Create the Agno agent with security analyst persona
        self.agent = Agent(
            name="Security Analyst",
            model=model,
            description="Expert Security Analyst for threat detection and analysis",
            instructions=[SYSTEM_PROMPT],
            markdown=True,
        )
    
    def analyze(
        self,
        events: list[SecurityEvent],
        vulnerabilities: list[Vulnerability],
        pre_correlated_incidents: list[Incident] = None,
        events_summary: dict = None
    ) -> AnalysisResult:
        """
        Perform AI-powered analysis on security artifacts.
        
        Args:
            events: List of security events to analyze
            vulnerabilities: List of vulnerabilities found
            pre_correlated_incidents: Incidents already detected by correlation engine
            events_summary: Summary statistics about events
            
        Returns:
            AnalysisResult with findings and recommendations
        """
        pre_correlated_incidents = pre_correlated_incidents or []
        events_summary = events_summary or {}
        
        # Prepare sample events for the prompt (limit to avoid token overflow)
        sample_events = self._prepare_sample_events(events, max_events=10)
        
        # Build the analysis prompt
        prompt = build_analysis_prompt(
            events_summary=events_summary,
            incidents=pre_correlated_incidents,
            vulnerabilities=vulnerabilities,
            sample_events=sample_events
        )
        
        # Get AI analysis
        print("  🤖 Querying AI model for analysis...")
        response = self.agent.run(prompt)
        
        # Parse the response
        raw_response = response.content if hasattr(response, 'content') else str(response)
        
        # Try to extract JSON from response
        analysis_data = self._parse_json_response(raw_response)
        
        # Build AnalysisResult
        result = self._build_analysis_result(
            analysis_data=analysis_data,
            events=events,
            vulnerabilities=vulnerabilities,
            pre_correlated_incidents=pre_correlated_incidents,
            raw_response=raw_response
        )
        
        return result
    
    def analyze_correlation(
        self,
        events: list[SecurityEvent]
    ) -> list[CorrelatedGroup]:
        """
        Use AI to find hidden correlations between events.
        
        Args:
            events: List of events to correlate
            
        Returns:
            List of AI-discovered correlated groups
        """
        # Prepare events as JSON
        events_json = json.dumps([
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "type": e.event_type,
                "source_ip": e.source_ip,
                "target_host": e.target_host,
                "username": e.username,
                "action": e.action,
                "outcome": e.outcome
            }
            for e in events
        ], indent=2)
        
        prompt = CORRELATION_PROMPT.format(events_json=events_json)
        
        print("  🔗 Querying AI for correlation insights...")
        response = self.agent.run(prompt)
        
        raw_response = response.content if hasattr(response, 'content') else str(response)
        
        # Parse correlation response
        correlation_data = self._parse_json_response(raw_response)
        
        groups = []
        for group in correlation_data.get("correlated_groups", []):
            # Find matching events
            event_ids = set(group.get("event_ids", []))
            matching_events = [e for e in events if e.id in event_ids]
            
            if matching_events:
                groups.append(CorrelatedGroup(
                    id=f"ai-grp-{uuid.uuid4().hex[:8]}",
                    events=matching_events,
                    correlation_type="ai",
                    correlation_reason=group.get("relationship", "AI-detected correlation"),
                    confidence=group.get("confidence", 0.7)
                ))
        
        return groups
    
    def _prepare_sample_events(
        self, 
        events: list[SecurityEvent], 
        max_events: int = 10
    ) -> str:
        """Prepare a sample of events as JSON for the prompt."""
        # Prioritize events that are likely more interesting
        # (failed logins, outbound transfers, privilege changes)
        priority_types = [
            "failed_login", "successful_login", "privilege_change",
            "outbound_transfer", "user_created", "malware_detected"
        ]
        
        prioritized = []
        other = []
        
        for event in events:
            if event.event_type in priority_types:
                prioritized.append(event)
            else:
                other.append(event)
        
        # Take priority events first, then fill with others
        sample = prioritized[:max_events]
        if len(sample) < max_events:
            sample.extend(other[:max_events - len(sample)])
        
        # Convert to JSON-friendly format
        sample_data = [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "type": e.event_type,
                "source_ip": e.source_ip,
                "target_host": e.target_host,
                "username": e.username,
                "action": e.action,
                "outcome": e.outcome,
                "details": e.details
            }
            for e in sample
        ]
        
        return json.dumps(sample_data, indent=2)
    
    def _parse_json_response(self, response: str) -> dict:
        """Extract JSON from the AI response."""
        # Try to find JSON in the response
        try:
            # Look for JSON block in markdown code fence
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                json_str = response[start:end].strip()
                return json.loads(json_str)
            elif "```" in response:
                start = response.find("```") + 3
                end = response.find("```", start)
                json_str = response[start:end].strip()
                return json.loads(json_str)
            else:
                # Try parsing the whole response
                return json.loads(response)
        except json.JSONDecodeError:
            # If JSON parsing fails, return structured fallback
            return {
                "executive_summary": "Analysis completed. See raw response for details.",
                "threat_level": "MEDIUM",
                "active_threats": [],
                "recommendations": [],
                "raw_text": response
            }
    
    def _build_analysis_result(
        self,
        analysis_data: dict,
        events: list[SecurityEvent],
        vulnerabilities: list[Vulnerability],
        pre_correlated_incidents: list[Incident],
        raw_response: str
    ) -> AnalysisResult:
        """Build an AnalysisResult from parsed AI response."""
        
        # Build incidents from AI-detected threats
        ai_incidents = []
        for threat in analysis_data.get("active_threats", []):
            mitre_techniques = [
                MITRETechnique(**get_mitre_technique(tid))
                for tid in threat.get("mitre_techniques", [])
            ]
            
            incident = Incident(
                id=f"ai-inc-{uuid.uuid4().hex[:8]}",
                title=threat.get("title", "AI-Detected Threat"),
                severity=Severity(threat.get("severity", "MEDIUM")),
                description=threat.get("description", ""),
                events=[],  # AI doesn't map to specific events
                mitre_techniques=mitre_techniques,
                affected_entities=threat.get("evidence", []),
                timeline=[],
                recommendations=[],
                confidence=threat.get("confidence", 0.8)
            )
            ai_incidents.append(incident)
        
        # Build recommendations
        recommendations = []
        for rec in analysis_data.get("recommendations", []):
            if isinstance(rec, dict):
                priority = rec.get("priority", "IMPORTANT")
                action = rec.get("action", str(rec))
                recommendations.append(f"[{priority}] {action}")
            else:
                recommendations.append(str(rec))
        
        # Combine pre-correlated incidents with AI-detected ones
        all_incidents = pre_correlated_incidents + ai_incidents
        
        return AnalysisResult(
            analysis_id=f"analysis-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(),
            total_events_analyzed=len(events),
            total_vulnerabilities=len(vulnerabilities),
            incidents=all_incidents,
            correlated_groups=[],  # Will be filled by correlation engine
            executive_summary=analysis_data.get("executive_summary", ""),
            detailed_findings=analysis_data.get("attack_narrative", ""),
            recommendations=recommendations,
            raw_ai_response=raw_response
        )
