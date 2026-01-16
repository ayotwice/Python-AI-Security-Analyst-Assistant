"""
AI-powered security analysis tool that ingests security artifacts,
correlates events, and uses an LLM via OpenRouter for expert analysis.
"""

from .models import (
    SecurityEvent,
    Vulnerability,
    Severity,
    EventType,
    Incident,
    CorrelatedGroup,
    AnalysisResult,
    MITRETechnique,
)
from .ingester import ArtifactIngester
from .correlator import CorrelationEngine
from .analyzer import SecurityAnalyzer
from .reporter import ReportGenerator

__version__ = "0.1.0"
__author__ = "Security Automation Engineer"

__all__ = [
    # Models
    "SecurityEvent",
    "Vulnerability", 
    "Severity",
    "EventType",
    "Incident",
    "CorrelatedGroup",
    "AnalysisResult",
    "MITRETechnique",
    # Components
    "ArtifactIngester",
    "CorrelationEngine",
    "SecurityAnalyzer",
    "ReportGenerator",
]
