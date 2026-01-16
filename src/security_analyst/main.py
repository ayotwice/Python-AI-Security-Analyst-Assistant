"""
AI Security Analyst - Main Entry Point

This is the main script that runs our security analysis tool.
It ties together all the components: ingestion, correlation, AI analysis, and reporting.

Usage:
    python -m security_analyst [OPTIONS] [DATA_PATH]
    
Examples:
    # Analyze sample data
    python -m security_analyst
    
    # Analyze custom data directory
    python -m security_analyst /path/to/data
    
    # Use specific model
    OPENROUTER_API_KEY=your_key python -m security_analyst
"""

import os
import sys
import argparse
from pathlib import Path
from datetime import timedelta

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from dotenv import load_dotenv

from .ingester import ArtifactIngester
from .correlator import CorrelationEngine
from .analyzer import SecurityAnalyzer
from .reporter import ReportGenerator, print_simple_report

# Load environment variables from .env file
load_dotenv()

console = Console()


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="AI-powered Security Analyst Tool",
        epilog="Example: python -m security_analyst ./data/samples"
    )
    
    parser.add_argument(
        "data_path",
        nargs="?",
        default=None,
        help="Path to directory containing security artifacts (default: ./data/samples)"
    )
    
    parser.add_argument(
        "--model",
        default=os.environ.get("MODEL_ID", "google/gemini-2.0-flash-001"),
        help="OpenRouter model ID (default: google/gemini-2.0-flash-001)"
    )
    
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI analysis (correlation only)"
    )
    
    parser.add_argument(
        "--simple",
        action="store_true",
        help="Use simple text output instead of Rich formatting"
    )
    
    parser.add_argument(
        "--time-window",
        type=int,
        default=10,
        help="Time window for correlation in minutes (default: 10)"
    )
    
    return parser.parse_args()


def main():
    """Main entry point for the security analyst tool."""
    args = parse_args()
    
    # Determine data path
    if args.data_path:
        data_path = Path(args.data_path)
    else:
        # Default to sample data in package
        data_path = Path(__file__).parent.parent.parent / "data" / "samples"
    
    if not data_path.exists():
        console.print(f"[red]Error:[/red] Data path not found: {data_path}")
        sys.exit(1)
    
    # Print banner
    console.print()
    console.print("[bold blue]╔══════════════════════════════════════════════════════════════╗[/bold blue]")
    console.print("[bold blue]║[/bold blue]           [bold white]🛡️  AI Security Analyst Tool[/bold white]                     [bold blue]║[/bold blue]")
    console.print("[bold blue]║[/bold blue]           [dim]Powered by Agno + OpenRouter[/dim]                       [bold blue]║[/bold blue]")
    console.print("[bold blue]╚══════════════════════════════════════════════════════════════╝[/bold blue]")
    console.print()
    
    # Check for API key if AI is enabled
    if not args.no_ai:
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            console.print("[red]Error:[/red] No API key found.")
            console.print("Set OPENROUTER_API_KEY in your .env file.")
            console.print()
            console.print("Example:")
            console.print("  export OPENROUTER_API_KEY=your_key_here")
            console.print()
            console.print("Or run with --no-ai to skip AI analysis.")
            sys.exit(1)
    
    # Run analysis with progress indicators
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        # Step 1: Load artifacts
        task = progress.add_task("[cyan]Loading security artifacts...", total=None)
        
        ingester = ArtifactIngester()
        events, vulnerabilities = ingester.load_from_directory(data_path)
        summary = ingester.get_summary(events, vulnerabilities)
        
        progress.update(task, description=f"[green]✓ Loaded {len(events)} events, {len(vulnerabilities)} vulnerabilities")
        progress.remove_task(task)
        
        console.print(f"  📄 Events: {len(events)}")
        console.print(f"  🔍 Vulnerabilities: {len(vulnerabilities)}")
        console.print()
        
        # Step 2: Run correlation engine
        task = progress.add_task("[cyan]Running correlation analysis...", total=None)
        
        correlator = CorrelationEngine()
        time_window = timedelta(minutes=args.time_window)
        correlated_groups, incidents = correlator.analyze(events, time_window)
        
        progress.update(task, description=f"[green]✓ Found {len(incidents)} correlated incidents")
        progress.remove_task(task)
        
        console.print(f"  🔗 Correlated groups: {len(correlated_groups)}")
        console.print(f"  🎯 Detected incidents: {len(incidents)}")
        console.print()
        
        # Step 3: AI Analysis (if enabled)
        if not args.no_ai:
            task = progress.add_task("[cyan]Running AI analysis...", total=None)
            
            try:
                analyzer = SecurityAnalyzer(model_id=args.model)
                result = analyzer.analyze(
                    events=events,
                    vulnerabilities=vulnerabilities,
                    pre_correlated_incidents=incidents,
                    events_summary=summary
                )
                
                progress.update(task, description="[green]✓ AI analysis complete")
                progress.remove_task(task)
                
            except Exception as e:
                progress.update(task, description=f"[red]✗ AI analysis failed: {e}")
                progress.remove_task(task)
                console.print(f"[yellow]Warning:[/yellow] AI analysis failed, using correlation results only.")
                console.print(f"[dim]Error: {e}[/dim]")
                console.print()
                
                # Create result from correlation only
                from .models import AnalysisResult
                from datetime import datetime
                result = AnalysisResult(
                    analysis_id="correlation-only",
                    timestamp=datetime.now(),
                    total_events_analyzed=len(events),
                    total_vulnerabilities=len(vulnerabilities),
                    incidents=incidents,
                    correlated_groups=correlated_groups,
                    executive_summary="AI analysis unavailable. Results based on correlation engine only.",
                    detailed_findings="",
                    recommendations=[inc.recommendations[0] for inc in incidents if inc.recommendations][:5]
                )
        else:
            # Correlation-only result
            from .models import AnalysisResult
            from datetime import datetime
            result = AnalysisResult(
                analysis_id="correlation-only",
                timestamp=datetime.now(),
                total_events_analyzed=len(events),
                total_vulnerabilities=len(vulnerabilities),
                incidents=incidents,
                correlated_groups=correlated_groups,
                executive_summary="Analysis based on correlation engine (AI analysis disabled).",
                detailed_findings="",
                recommendations=[inc.recommendations[0] for inc in incidents if inc.recommendations][:5]
            )
        
        # Add correlated groups to result
        result.correlated_groups = correlated_groups
    
    console.print()
    
    # Step 4: Generate report
    if args.simple:
        print_simple_report(result)
    else:
        reporter = ReportGenerator()
        reporter.generate(result)


if __name__ == "__main__":
    main()
