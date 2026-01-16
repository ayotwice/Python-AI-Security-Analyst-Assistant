"""
Log Streamer Simulator for Security Analyst Tool.

"""

import time
import json
import random
from datetime import datetime
from pathlib import Path

from .models import SecurityEvent
from .ingester import ArtifactIngester

def stream_logs(interval_seconds: float = 2.0, max_events: int = 10000):
    """
    Continually writes logs to a JSON buffer file to simulate 
    a live streaming environment for DuckDB to query.
    """
    ingester = ArtifactIngester()
    buffer_path = Path("data/streaming_logs.json")
    buffer_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Load sample logs
    sample_path = Path("data/samples/siem_logs.json")
    if not sample_path.exists():
        print(f"❌ Sample logs not found at {sample_path}")
        return
        
    all_events = ingester.load_siem_logs(str(sample_path))
    print(f"📦 Loaded {len(all_events)} sample events for streaming.")
    
    # Initialize buffer with an empty list if it doesn't exist
    if not buffer_path.exists():
        with open(buffer_path, "w") as f:
            json.dump([], f)

    event_count = 0
    try:
        while event_count < max_events:
            # Pick a random event from samples
            event = random.choice(all_events)
            
            # Update timestamp to "now"
            event.timestamp = datetime.now()
            # Give it a unique ID
            event.id = f"stream-{event_count}-{random.randint(1000, 9999)}"
            
            # Read current buffer
            try:
                with open(buffer_path, "r") as f:
                    current_logs = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                current_logs = []
                
            # Append new event
            current_logs.append(event.model_dump(mode='json'))
            
            # Keep only last 1000 events to avoid massive files
            if len(current_logs) > 1000:
                current_logs = current_logs[-1000:]
                
            # Write back
            with open(buffer_path, "w") as f:
                json.dump(current_logs, f, indent=2)
            
            event_count += 1
            print(f"🚀 [{datetime.now().strftime('%H:%M:%S')}] Streamed event {event_count}: {event.event_type}")
            
            time.sleep(interval_seconds)
            
    except KeyboardInterrupt:
        print("\n🛑 Stream stopped.")
    finally:
        print(f"🏁 Streamed {event_count} total events.")

if __name__ == "__main__":
    stream_logs()
