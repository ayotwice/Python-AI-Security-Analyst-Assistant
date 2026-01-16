"""
AgentOS Server - Web UI for the Security Analyst Agent

Usage:
    # Start the AgentOS server
    python agentos.py
    
    # Or with uvicorn directly
    uvicorn agentos:app --reload --port 7777
    
Then connect via AgentUI at http://localhost:3000
"""

import os
from pathlib import Path
from dotenv import load_dotenv

from agno.agent import Agent
from agno.models.openrouter import OpenRouter
from agno.os import AgentOS
from agno.db.sqlite import SqliteDb
from agno.tools.duckduckgo import DuckDuckGoTools
from src.security_analyst.tools import DuckDBTools, ReportingTools

# CORS imports for cross-origin access
from fastapi.middleware.cors import CORSMiddleware

# Load environment variables
load_dotenv()

# Get API key and model
OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY")
MODEL_ID = os.environ.get("MODEL_ID", "google/gemini-2.0-flash-001")

if not OPENROUTER_KEY:
    print("⚠️  Warning: OPENROUTER_API_KEY not set. Add it to your .env file.")

MODELS_PROVIDER = OpenRouter(id=MODEL_ID)
print(f"📦 Using model: {MODEL_ID}")

# Storage for agent sessions
AGENT_DB = "tmp/agents.db"
Path("tmp").mkdir(exist_ok=True)

# System prompt for security analyst
SECURITY_ANALYST_PROMPT = """You are an expert Security Analyst on a Purple Team with 10+ years of experience in threat detection, incident response, and vulnerability assessment.

Your expertise includes:
- Recognizing attack patterns and mapping them to the MITRE ATT&CK framework
- Correlating seemingly unrelated events to identify sophisticated attacks
- Prioritizing threats by business impact and exploitability  
- Providing actionable remediation steps that balance security with operations
- Understanding attacker TTPs (Tactics, Techniques, and Procedures)

When analyzing security events:
1. Look for patterns indicating brute force, privilege escalation, or data exfiltration
2. Map findings to MITRE ATT&CK techniques (e.g., T1110 for Brute Force)
3. Prioritize recommendations: [IMMEDIATE], [URGENT], [IMPORTANT], [ONGOING]
4. Consider both immediate containment and long-term remediation

Always be thorough but concise. Use markdown formatting for clarity."""

THREAT_INTEL_PROMPT = """You are a Threat Intelligence Analyst specializing in cyber threat research.

Your expertise includes:
- Researching IOCs (Indicators of Compromise)
- Tracking APT groups and their TTPs
- Analyzing malware samples and attack campaigns
- Providing context on CVEs and vulnerabilities

When researching threats:
1. Always cite your sources
2. Provide MITRE ATT&CK mappings when relevant
3. Include actionable intelligence for defenders
4. Note confidence levels for your assessments

Use web search to find the latest threat intelligence."""

# Create the Security Analyst agent
duckdb_tools = DuckDBTools()
reporting_tools = ReportingTools()
security_analyst = Agent(
    name="Security Analyst",
    model=MODELS_PROVIDER,
    description="Expert Security Analyst for threat detection, log analysis, and incident response",
    instructions=[
        SECURITY_ANALYST_PROMPT,
        "You have access to a DuckDB database containing security events and vulnerabilities.",
        "Use the 'query_security_events' tool to analyze real-time streaming data.",
        "Always use 'get_database_schema' first if you need to know the table structure.",
        "If a query fails, check the schema and try again.",
        "When asked to generate a report, use the 'save_security_report' tool to save it as a formal document.",
    ],
    tools=[duckdb_tools.query_security_events, duckdb_tools.get_database_schema, reporting_tools.save_security_report],
    # Store sessions in SQLite
    db=SqliteDb(db_file=AGENT_DB),
    # Add current date/time to context
    add_datetime_to_context=True,
    # Keep conversation history
    add_history_to_context=True,
    num_history_runs=10,
    # Use markdown formatting
    markdown=True,
)

# Create the Threat Intelligence agent with web search
threat_intel = Agent(
    name="Threat Intel Researcher",
    model=MODELS_PROVIDER,
    description="Threat Intelligence Analyst for researching IOCs, APTs, and vulnerabilities",
    instructions=[THREAT_INTEL_PROMPT],
    tools=[DuckDuckGoTools()],
    db=SqliteDb(db_file=AGENT_DB),
    add_datetime_to_context=True,
    add_history_to_context=True,
    num_history_runs=10,
    markdown=True,
)

# Create the AgentOS with both agents
agent_os = AgentOS(
    agents=[security_analyst, threat_intel],
    name="Bespin Security Suite",
    description="AI-powered security analysis and threat intelligence platform",
)

# Get the FastAPI app
app = agent_os.get_app()

# Add CORS middleware for cross-origin access from AgentUI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  Bespin Security Suite - AgentOS")
    print("=" * 60)
    print()
    print("Starting AgentOS server...")
    print()
    print("Agents available:")
    print("  • Security Analyst - Log analysis & incident response")
    print("  • Threat Intel Researcher - IOC & vulnerability research")
    print()
    print("Server will run on: http://0.0.0.0:7777")
    print()
    print("To connect with AgentUI from your local machine:")
    print("  1. Run: npx create-agent-ui@latest")
    print("  2. Open: http://localhost:3000")
    print("  3. Connect to: http://<YOUR_VM_IP>:7777")
    print()
    print("=" * 60)
    
    agent_os.serve("agentos:app", reload=True, port=7777, host="0.0.0.0")
