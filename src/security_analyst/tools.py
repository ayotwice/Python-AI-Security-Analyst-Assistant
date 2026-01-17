"""
DuckDB Analysis Tools for Agno Agents.

Provides tools for the agent to query the persistent security database.
"""

import json
from pathlib import Path
from datetime import datetime

import duckdb


DB_PATH = "data/security.duckdb"


class ReportingTools:
    """Tools for generating and saving security reports."""
    
    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
    def save_security_report(self, title: str, content: str) -> str:
        """
        Saves a formal security report as a markdown file.
        
        Args:
            title: The title of the report (will be used for filename)
            content: The markdown content of the report
            
        Returns:
            The path to the saved report.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = "".join([c if c.isalnum() else "_" for c in title])
        filename = f"report_{safe_title}_{timestamp}.md"
        report_path = self.reports_dir / filename
        
        with open(report_path, "w") as f:
            f.write(f"# {title}\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(content)
            
        return f"Successfully saved formal report to: {report_path.absolute()}"


class DuckDBTools:
    """Tools for querying the persistent security database."""
    
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        
    def query_security_events(self, sql_query: str) -> str:
        """
        Run a SQL query against the security events database.
        
        The database contains:
        - 'events' table: Real-time streaming security events
        - 'vulnerabilities' table: Vulnerability scan results
        
        Example queries:
        - SELECT * FROM events WHERE event_type = 'failed_login' LIMIT 10
        - SELECT event_type, COUNT(*) FROM events GROUP BY event_type
        - SELECT * FROM vulnerabilities WHERE severity = 'CRITICAL'
        """
        # Check if database exists
        if not Path(self.db_path).exists():
            return "Database not found. Please start the streamer first: python -m security_analyst.streamer"
        
        try:
            conn = duckdb.connect(self.db_path, read_only=True)
            
            result = conn.execute(sql_query)
            columns = [desc[0] for desc in result.description]
            rows = result.fetchall()
            
            conn.close()
            
            if not rows:
                return "No results found for that query."
            
            # Convert to list of dicts
            results = [dict(zip(columns, row)) for row in rows]
            return json.dumps(results, indent=2, default=str)
            
        except Exception as e:
            return f"Error executing query: {str(e)}"

    def get_database_schema(self) -> str:
        """
        Returns the schema of the security database.
        Use this to understand what tables and columns are available.
        """
        return """
Database: data/security.duckdb

Table: events
- id: unique event identifier (VARCHAR)
- timestamp: time of the event (TIMESTAMP)
- event_type: category of event like failed_login, successful_login, file_access, etc. (VARCHAR)
- source_ip: originating IP address (VARCHAR)
- target_host: destination host (VARCHAR)
- target_port: destination port (INTEGER)
- username: user involved in the event (VARCHAR)
- action: what was done (VARCHAR)
- outcome: success/failure/blocked (VARCHAR)
- severity: severity level (VARCHAR)
- details: JSON blob with extra info (JSON)

Table: vulnerabilities
- id: unique vulnerability identifier (VARCHAR)
- cve_id: CVE identifier e.g. CVE-2021-44228 (VARCHAR)
- title: Name of the vulnerability (VARCHAR)
- severity: CRITICAL, HIGH, MEDIUM, LOW (VARCHAR)
- description: Detailed description (VARCHAR)
- affected_host: Host where vulnerability was found (VARCHAR)
- affected_software: Vulnerable software name (VARCHAR)
- cvss_score: Numerical risk score 0-10 (FLOAT)
- remediation: Recommended fix (VARCHAR)
- discovered_at: When the scan was run (TIMESTAMP)

Example queries:
- Get recent events: SELECT * FROM events ORDER BY timestamp DESC LIMIT 20
- Count by type: SELECT event_type, COUNT(*) as cnt FROM events GROUP BY event_type ORDER BY cnt DESC
- Failed logins: SELECT * FROM events WHERE event_type = 'failed_login' ORDER BY timestamp DESC
- Critical vulns: SELECT * FROM vulnerabilities WHERE severity = 'CRITICAL'
        """
    
    def get_event_summary(self) -> str:
        """
        Get a quick summary of the current events in the database.
        """
        if not Path(self.db_path).exists():
            return "Database not found. Please start the streamer first."
        
        try:
            conn = duckdb.connect(self.db_path, read_only=True)
            
            summary = {}
            
            # Total events
            result = conn.execute("SELECT COUNT(*) FROM events").fetchone()
            summary["total_events"] = result[0]
            
            # Events by type
            result = conn.execute("""
                SELECT event_type, COUNT(*) as cnt 
                FROM events 
                GROUP BY event_type 
                ORDER BY cnt DESC
            """).fetchall()
            summary["events_by_type"] = {row[0]: row[1] for row in result}
            
            # Time range
            result = conn.execute("""
                SELECT MIN(timestamp), MAX(timestamp) FROM events
            """).fetchone()
            summary["time_range"] = {
                "earliest": str(result[0]),
                "latest": str(result[1])
            }
            
            # Total vulnerabilities
            result = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()
            summary["total_vulnerabilities"] = result[0]
            
            conn.close()
            
            return json.dumps(summary, indent=2, default=str)
            
        except Exception as e:
            return f"Error getting summary: {str(e)}"
