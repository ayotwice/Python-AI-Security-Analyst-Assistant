"""
DuckDB Analysis Tools for Agno Agents.
"""

import json
from pathlib import Path
from datetime import datetime

class ReportingTools:
    """
    Tools for generating and saving security reports.
    """
    
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
    """
    Tools for querying the security database.
    """
    
    def __init__(self, db_path: str = "data/security.duckdb"):
        self.db_path = db_path
        
    def query_security_events(self, sql_query: str) -> str:
        """
        Run a SQL query against the security events database and return results.
        
        The 'events' table contains real-time streaming data.
        The 'vulnerabilities' table contains the latest scan results.
        """
        import duckdb
        # Use in-memory DuckDB to avoid locking issues
        conn = duckdb.connect(":memory:")
        
        try:
            # Create views from JSON files
            events_json = "data/streaming_logs.json"
            vulns_json = "data/samples/vulnerability_scan.json"
            
            conn.execute(f"CREATE VIEW events AS SELECT * FROM read_json_auto('{events_json}')")
            conn.execute(f"CREATE VIEW vulnerabilities AS SELECT * FROM read_json_auto('{vulns_json}')")
            
            # Execute the user's query
            # We fetch as a pandas dataframe and convert to dict for easy JSON serialization
            results = conn.execute(sql_query).fetchdf().to_dict('records')
            
            if not results:
                return "No results found for that query."
            return json.dumps(results, indent=2, default=str)
        except Exception as e:
            return f"Error executing query: {str(e)}"
        finally:
            conn.close()

    def get_database_schema(self) -> str:
        """
        Returns the schema of the security database.
        Use this to understand what tables and columns are available.
        """
        return """
        Table: events
        - id: unique event identifier
        - timestamp: time of the event
        - event_type: category of event (login, file_access, etc.)
        - source_ip: originating IP address
        - target_host: destination host
        - username: user involved in the event
        - action: what was done
        - outcome: success/failure
        - severity: severity level
        - details: JSON blob with extra info
        
        Table: vulnerabilities
        - id: unique vulnerability identifier
        - cve_id: CVE identifier (e.g., CVE-2021-44228)
        - title: Name of the vulnerability
        - severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        - description: Detailed description
        - affected_host: Host where vulnerability was found
        - affected_software: Vulnerable software name
        - cvss_score: Numerical risk score (0-10)
        - remediation: Recommended fix
        """
