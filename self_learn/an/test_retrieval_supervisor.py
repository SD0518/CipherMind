"""
Test script for the new Retrieval Supervisor pipeline.

This script uses the RetrievalSupervisor class to run the complete retrieval pipeline
on log analysis reports, providing comprehensive threat intelligence and MITRE ATT&CK
technique retrieval.
"""

import os
from dotenv import load_dotenv
from langchain.chat_models import init_chat_model
import sys
import json
import argparse
from typing import Dict, Any, Optional
from pathlib import Path


# Add the project root to Python path so we can import from src
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Import the RetrievalSupervisor
try:
    from src.agents.retrieval_supervisor.supervisor import RetrievalSupervisor
except ImportError as e:
    print(f"[ERROR] Could not import RetrievalSupervisor: {e}")
    print("Please ensure the supervisor.py file is in the correct location.")
    sys.exit(1)

load_dotenv()
os.environ["GOOGLE_API_KEY"] = os.getenv("GOOGLE_API_KEY")


def load_log_analysis_report(file_path: str) -> Dict[str, Any]:
    """Load log analysis report from JSON file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        print(f"[SUCCESS] Loaded log analysis report from {file_path}")
        return report
    except FileNotFoundError:
        print(f"[ERROR] Log analysis report file not found: {file_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in log analysis report: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Error loading report: {e}")
        sys.exit(1)


def validate_report_structure(report: Dict[str, Any]) -> bool:
    """Validate that the report has the expected structure."""
    required_fields = ["overall_assessment", "analysis_summary"]

    for field in required_fields:
        if field not in report:
            print(f"[WARNING] Missing field '{field}' in report")
            return False

    # Check for abnormal events if present
    if "abnormal_events" in report:
        if not isinstance(report["abnormal_events"], list):
            print("[WARNING] 'abnormal_events' should be a list")
            return False

        for i, event in enumerate(report["abnormal_events"]):
            if not isinstance(event, dict):
                print(f"[WARNING] Event {i} is not a dictionary")
                return False

            event_required = [
                "event_id",
                "event_description",
                "why_abnormal",
                "severity",
            ]
            for field in event_required:
                if field not in event:
                    print(f"[WARNING] Event {i} missing field '{field}'")
                    return False

    return True


def run_retrieval_pipeline(
    report_path: str,
    llm_model: str = "google_genai:gemini-2.5-flash",
    kb_path: str = "./cyber_knowledge_base",
    max_iterations: int = 3,
    context: Optional[str] = None,
    interactive: bool = False,
):
    """Run the complete retrieval pipeline using RetrievalSupervisor."""

    # Load the log analysis report
    report = load_log_analysis_report(report_path)

    # Validate report structure
    if not validate_report_structure(report):
        print("[WARNING] Report structure validation failed, but continuing...")

    # Initialize the RetrievalSupervisor
    print("\n" + "=" * 60)
    print("INITIALIZING RETRIEVAL SUPERVISOR")
    print("=" * 60)

    try:
        supervisor = RetrievalSupervisor(
            llm_model=llm_model,
            kb_path=kb_path,
            max_iterations=max_iterations,
        )
    except Exception as e:
        print(f"[ERROR] Failed to initialize RetrievalSupervisor: {e}")
        return None

    # Generate query based on report content
    query = "Analyze this IOCs report from log analysis agent and retrieve relevant MITRE ATT&CK techniques"

    print("\n" + "=" * 60)
    print("RUNNING RETRIEVAL PIPELINE")
    print("=" * 60)
    print(f"Query: {query}")
    print(f"Report Assessment: {report.get('overall_assessment', 'Unknown')}")
    print(f"Context: {context}")
    print()

    # Execute the retrieval pipeline
    try:
        results = supervisor.invoke(
            query=query,
            log_analysis_report=report,
            context=context,
            trace=True,
        )

        # Display results
        display_results(results)

        return results

    except Exception as e:
        print(f"[ERROR] Pipeline execution failed: {e}")
        return None


def generate_query_from_report(report: Dict[str, Any]) -> str:
    """Generate a comprehensive query based on the log analysis report."""

    # Base query components
    query_parts = [
        "Analyze the detected security anomalies and provide comprehensive threat intelligence."
    ]

    # Add specific analysis based on report content
    if "abnormal_events" in report and report["abnormal_events"]:
        query_parts.append("Focus on the following detected anomalies:")

        for i, event in enumerate(
            report["abnormal_events"][:3], 1
        ):  # Limit to top 3 events
            event_desc = event.get("event_description", "Unknown event")
            threat = event.get("potential_threat", "Unknown threat")
            category = event.get("attack_category", "Unknown category")

            query_parts.append(
                f"{i}. {event_desc} - Potential: {threat} (Category: {category})"
            )

    # Add analysis summary if available
    if "analysis_summary" in report:
        query_parts.append(f"Analysis Summary: {report['analysis_summary']}")

    # Add specific intelligence requirements
    query_parts.extend(
        [
            "",
            "Please provide:",
            "1. Relevant threat intelligence from CTI sources",
            "2. MITRE ATT&CK technique mapping and tactical analysis",
            "3. Actionable recommendations for threat hunting and defense",
            "4. IOCs and indicators for detection rules",
        ]
    )

    return "\n".join(query_parts)


def display_results(results: Dict[str, Any]):
    """Display the retrieval results in a formatted way."""

    print("\n" + "=" * 60)
    print("RETRIEVAL RESULTS")
    print("=" * 60)

    # Basic status information
    print(f"Status: {results.get('status', 'Unknown')}")
    print(f"Final Assessment: {results.get('final_assessment', 'Unknown')}")
    print(f"Agents Used: {', '.join(results.get('agents_used', []))}")
    print(f"Summary: {results.get('summary', 'No summary available')}")
    print(f"Total Techniques: {results.get('total_techniques', 0)}")
    print(f"Iteration Count: {results.get('iteration_count', 0)}")

    # Display structured techniques
    retrieved_techniques = results.get("retrieved_techniques", [])
    if retrieved_techniques:
        print(f"\nRetrieved MITRE Techniques ({len(retrieved_techniques)}):")
        for i, technique in enumerate(retrieved_techniques, 1):
            print(f"\n  {i}. {technique.get('technique_id', 'N/A')}: {technique.get('technique_name', 'N/A')}")
            print(f"     Tactic: {technique.get('tactic', 'N/A')}")
            print(f"     Relevance Score: {technique.get('relevance_score', 0)}")
            description = technique.get('description', 'No description')
            if len(description) > 100:
                description = description[:100] + "..."
            print(f"     Description: {description}")
    else:
        print("\nNo techniques retrieved")

    # Display recommendations (if available)
    recommendations = results.get("recommendations", [])
    if recommendations:
        print(f"\nRecommendations ({len(recommendations)}):")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")

    # Display detailed results (legacy format for backward compatibility)
    detailed_results = results.get("results", {})
    if detailed_results:
        print(f"\nDetailed Results (Legacy Format):")

        # CTI Intelligence
        cti_intelligence = detailed_results.get("cti_intelligence", [])
        if cti_intelligence:
            print(f"\n  CTI Intelligence ({len(cti_intelligence)} sources):")
            for i, cti in enumerate(cti_intelligence, 1):
                preview = str(cti)[:200] + "..." if len(str(cti)) > 200 else str(cti)
                print(f"    {i}. {preview}")

        # MITRE Techniques
        mitre_techniques = detailed_results.get("mitre_techniques", [])
        if mitre_techniques:
            print(f"\n  MITRE Techniques ({len(mitre_techniques)} retrieved):")
            for i, technique in enumerate(mitre_techniques, 1):
                preview = (
                    str(technique)[:200] + "..."
                    if len(str(technique)) > 200
                    else str(technique)
                )
                print(f"    {i}. {preview}")

        # Quality Assessments
        quality_assessments = detailed_results.get("quality_assessments", [])
        if quality_assessments:
            print(f"\n  Quality Assessments ({len(quality_assessments)}):")
            for i, assessment in enumerate(quality_assessments, 1):
                preview = (
                    str(assessment)[:200] + "..."
                    if len(str(assessment)) > 200
                    else str(assessment)
                )
                print(f"    {i}. {preview}")

    print("\n" + "=" * 60)


def interactive_mode():
    """Run in interactive mode for multiple reports."""
    print("\n=== INTERACTIVE MODE ===")
    print("Enter path to a log analysis JSON report, or 'quit' to exit:")

    # Get initial configuration
    model = (
        input("LLM Model (default: google_genai:gemini-2.5-flash): ").strip()
        or "google_genai:gemini-2.5-flash"
    )
    kb_path = (
        input("Knowledge Base Path (default: ./cyber_knowledge_base): ").strip()
        or "./cyber_knowledge_base"
    )

    while True:
        user_input = input("\nReport JSON path: ").strip()
        if user_input.lower() in ["quit", "exit", "q"]:
            break

        if user_input:
            try:
                run_retrieval_pipeline(
                    report_path=user_input,
                    llm_model=model,
                    kb_path=kb_path,
                    interactive=False,
                )
            except Exception as e:
                print(f"Error: {str(e)}")


def main():
    """Main function to run the retrieval pipeline."""

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Test the new Retrieval Supervisor pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_new_retrieval_supervisor.py report.json
  python test_new_retrieval_supervisor.py report.json --model google_genai:gemini-2.5-flash
  python test_new_retrieval_supervisor.py report.json --interactive
  python test_new_retrieval_supervisor.py report.json --context "Urgent security incident"
        """,
    )

    parser.add_argument("report_path", help="Path to the log analysis report JSON file")

    parser.add_argument(
        "--model",
        default="google_genai:gemini-2.0-flash",
        help="LLM model name (default: google_genai:gemini-2.0-flash)",
    )

    parser.add_argument(
        "--kb-path",
        default="./cyber_knowledge_base",
        help="Path to the cyber knowledge base directory (default: ./cyber_knowledge_base)",
    )

    parser.add_argument(
        "--max-iterations",
        type=int,
        default=3,
        help="Maximum iterations for the retrieval pipeline (default: 3)",
    )

    parser.add_argument(
        "--context", help="Additional context for the analysis (optional)"
    )

    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Run in interactive mode after pipeline completion",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    args = parser.parse_args()

    # Validate report path
    if not os.path.exists(args.report_path):
        print(f"[ERROR] Report file not found: {args.report_path}")
        sys.exit(1)

    # Validate knowledge base path
    if not os.path.exists(args.kb_path):
        print(f"[WARNING] Knowledge base path not found: {args.kb_path}")
        print(
            "The pipeline may fail if the knowledge base is not properly initialized."
        )

    # Run the retrieval pipeline
    try:
        results = run_retrieval_pipeline(
            report_path=args.report_path,
            llm_model=args.model,
            kb_path=args.kb_path,
            max_iterations=args.max_iterations,
            context=args.context,
            interactive=args.interactive,
        )

        if results is None:
            print("[ERROR] Pipeline execution failed")
            sys.exit(1)

        # Interactive mode
        if args.interactive:
            interactive_mode()

        print("\n[SUCCESS] Pipeline completed successfully!")

    except KeyboardInterrupt:
        print("\n[INFO] Pipeline interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
