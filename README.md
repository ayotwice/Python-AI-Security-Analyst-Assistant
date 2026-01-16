> **Note:** This project was developed with AI assistance (Gemini).

# AI Security Analyst Assistant 

An AI-powered security analysis tool that ingests security artifacts, correlates events using pattern matching and MITRE ATT&CK mapping, and leverages an LLM (via OpenRouter) for expert-level threat analysis.

## What it does

1. **Ingests data** - Reads JSON files containing SIEM-style logs and vuln scan results
2. **Correlates events** - Groups related events by time, IP/user/host, and matches against known attack patterns (MITRE ATT&CK mapped)
3. **AI analysis**  - Sends the correlated data to an LLM for a more narrative threat assessment
4. **Prints a report** - Color-coded console output with severity levels and recommendations

## Setup

```bash
# Install deps (I used uv, but pip works too)
uv sync
# or: pip install -r requirements.txt

# Copy env file and add your OpenRouter key
cp .env.example .env
# edit .env and add: OPENROUTER_API_KEY=your_key
```

## Running it

```bash
# With sample data
python -m security_analyst

# Point to your own data
python -m security_analyst /path/to/data

# Skip the AI part (just correlation)
python -m security_analyst --no-ai
```

## Web UI

There's also a chat interface if you want to interact with the agent:

```bash
# Terminal 1: backend
python agentos.py

# Terminal 2: frontend
cd agent-ui && npm run dev
```

Then hit http://localhost:3000 and connect to http://localhost:7777.

## Project layout

```
src/security_analyst/
├── main.py         # CLI entry point
├── ingester.py     # Loads JSON artifacts
├── correlator.py   # Time/entity/pattern correlation
├── patterns.py     # MITRE ATT&CK pattern definitions
├── analyzer.py     # Agno agent + OpenRouter integration
├── prompts.py      # System/analysis prompts for the LLM
├── reporter.py     # Rich console output
├── models.py       # Pydantic data models
└── tools.py        # DuckDB query tools for the agent
```

## Sample data

The `data/samples/` folder has synthetic logs that simulate a basic attack chain: brute force → login → add user → privesc → exfil. I generated these to test the correlation logic.

## Limitations

- JSON only (no CSV, Splunk exports, etc.)
- Batch processing only (no streaming)
- Token limits can be an issue with large datasets

## Future ideas

If I had more time:
- DuckDB/ClickHouse for larger datasets
- Multi-agent setup (triage agent → investigation agent)
- RAG with threat intel feeds
- REST API for integration

---

Built with Python, Agno, OpenRouter, DuckDB, and Rich.
