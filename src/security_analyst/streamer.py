"""
Log Streamer with Persistent DuckDB Storage.

Streams events directly into a DuckDB database for the agent to query.
"""

import time
import json
import random
from datetime import datetime
from pathlib import Path

import duckdb

from .models import SecurityEvent
from .ingester import ArtifactIngester


DB_PATH = "data/security.duckdb"


def init_database():
    """Initialize the DuckDB database with the events table."""
    Path("data").mkdir(parents=True, exist_ok=True)
    conn = duckdb.connect(DB_PATH)
    
    # Enable WAL mode for better concurrent access
    conn.execute("PRAGMA enable_progress_bar")
    
    # Create events table if it doesn't exist
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id VARCHAR PRIMARY KEY,
            timestamp TIMESTAMP,
            event_type VARCHAR,
            source_ip VARCHAR,
            target_host VARCHAR,
            target_port INTEGER,
            username VARCHAR,
            action VARCHAR,
            outcome VARCHAR,
            severity VARCHAR,
            details JSON
        )
    """)
    
    # Create vulnerabilities table if it doesn't exist
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id VARCHAR PRIMARY KEY,
            cve_id VARCHAR,
            title VARCHAR,
            severity VARCHAR,
            description VARCHAR,
            affected_host VARCHAR,
            affected_software VARCHAR,
            cvss_score FLOAT,
            remediation VARCHAR,
            discovered_at TIMESTAMP
        )
    """)
    
    conn.close()
    print(f"✅ Database initialized at {DB_PATH}")


def load_vulnerabilities():
    """Load vulnerabilities from JSON into DuckDB."""
    conn = duckdb.connect(DB_PATH)
    vulns_path = Path("data/samples/vulnerability_scan.json")
    
    if vulns_path.exists():
        with open(vulns_path) as f:
            vulns = json.load(f)
        
        for v in vulns:
            conn.execute("""
                INSERT OR REPLACE INTO vulnerabilities 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                v.get("id"),
                v.get("cve_id"),
                v.get("title"),
                v.get("severity"),
                v.get("description"),
                v.get("affected_host"),
                v.get("affected_software"),
                v.get("cvss_score"),
                v.get("remediation"),
                datetime.now()
            ])
        
        print(f"📦 Loaded {len(vulns)} vulnerabilities into database")
    
    conn.close()


def stream_logs(interval_seconds: float = 2.0, max_events: int = 10000):
    """
    Stream logs directly into DuckDB for real-time querying.
    """
    # Initialize database
    init_database()
    load_vulnerabilities()
    
    ingester = ArtifactIngester()
    
    # Load sample logs
    sample_path = Path("data/samples/siem_logs.json")
    if not sample_path.exists():
        print(f"❌ Sample logs not found at {sample_path}")
        return
        
    all_events = ingester.load_siem_logs(str(sample_path))
    print(f"📦 Loaded {len(all_events)} sample events for streaming.")
    
    event_count = 0
    
    try:
        while event_count < max_events:
            # Pick a random event from samples
            event = random.choice(all_events)
            
            # Update timestamp to "now" and give unique ID
            event.timestamp = datetime.now()
            event.id = f"stream-{event_count}-{random.randint(1000, 9999)}"
            
            # Open fresh connection for each write (allows concurrent reads)
            conn = duckdb.connect(DB_PATH)
            
            # Insert into DuckDB
            conn.execute("""
                INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                event.id,
                event.timestamp,
                event.event_type,
                event.source_ip,
                event.target_host,
                event.target_port,
                event.username,
                event.action,
                event.outcome,
                getattr(event, 'severity', None),
                json.dumps(event.details) if event.details else None
            ])
            
            # Keep table size manageable (last 5000 events)
            if event_count % 100 == 0:
                conn.execute("""
                    DELETE FROM events 
                    WHERE id NOT IN (
                        SELECT id FROM events ORDER BY timestamp DESC LIMIT 5000
                    )
                """)
            
            conn.close()
            
            event_count += 1
            print(f"🚀 [{datetime.now().strftime('%H:%M:%S')}] Streamed event {event_count}: {event.event_type}")
            
            time.sleep(interval_seconds)
            
    except KeyboardInterrupt:
        print("\n🛑 Stream stopped.")
    finally:
        print(f"🏁 Streamed {event_count} total events.")


if __name__ == "__main__":
    stream_logs()
