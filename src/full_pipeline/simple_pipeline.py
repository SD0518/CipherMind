#!/usr/bin/env python3
"""
Simple Integrated Pipeline - Direct connection between Log Analysis Agent and Retrieval Supervisor

This file replaces the complex full_pipeline structure with a straightforward LangGraph
that passes log analysis results directly to the retrieval supervisor.
"""
# --model groq:openai/gpt-oss-120b
import os
import sys
import time
from pathlib import Path
from typing import Dict, Any, TypedDict
from langchain.chat_models import init_chat_model
from dotenv import load_dotenv

# LangGraph imports
from langgraph.graph import StateGraph, END, START
from langchain_core.messages import HumanMessage

# Add project root to path for agent imports
# Since we're in src/full_pipeline/, go up two levels to project root
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.agents.log_analysis_agent.agent import LogAnalysisAgent
from src.agents.retrieval_supervisor.supervisor import RetrievalSupervisor
from src.agents.response_agent.response_agent import ResponseAgent


# Simple state for the pipeline
class PipelineState(TypedDict):
    log_file: str
    log_analysis_result: Dict[str, Any]
    retrieval_result: Dict[str, Any]
    response_analysis: Dict[str, Any]
    query: str
    tactic: str
    markdown_report: str


def create_simple_pipeline(
    model_name: str = "google_genai:gemini-2.0-flash",
    temperature: float = 0.1,
    max_log_analysis_iterations: int = 2,
    max_retrieval_iterations: int = 2,
    log_agent_output_dir: str = "analysis",
    response_agent_output_dir: str = "final_response",
    progress_callback=None,
):
    # Initialize LLM client directly
    print("\n" + "=" * 60)
    print("INITIALIZING LLM CLIENT")
    print("=" * 60)
    print(f"Model: {model_name}")
    print(f"Temperature: {temperature}")
    print("=" * 60 + "\n")

    if "gpt-oss" in model_name and "groq" in model_name:
        reasoning_effort = "medium"
        reasoning_format = "hidden"
        llm_client = init_chat_model(
            model_name,
            temperature=temperature,
            reasoning_effort=reasoning_effort,
            reasoning_format=reasoning_format,
        )
        print(
            f"[INFO] Using GPT-OSS model: {model_name} with reasoning effort: {reasoning_effort}"
        )
    elif "gpt-5" in model_name and "openai" in model_name:
        reasoning_effort = "minimal"
        llm_client = init_chat_model(
            model_name,
            reasoning_effort=reasoning_effort,
        )
        print(
            f"[INFO] Using GPT-5 family model: {model_name} with reasoning effort: {reasoning_effort}"
        )
    else:
        llm_client = init_chat_model(model_name, temperature=temperature)
        print(f"[INFO] Initialized with {model_name}")

    # Initialize agents with shared LLM client
    log_agent = LogAnalysisAgent(
        model_name=model_name,
        output_dir=log_agent_output_dir,
        max_iterations=max_log_analysis_iterations,
        llm_client=llm_client,
    )

    retrieval_supervisor = RetrievalSupervisor(
        kb_path="./cyber_knowledge_base",
        max_iterations=max_retrieval_iterations,
        llm_client=llm_client,
    )

    response_agent = ResponseAgent(
        model_name=model_name,
        output_dir=response_agent_output_dir,
        llm_client=llm_client,
    )

    def run_log_analysis(state: PipelineState) -> PipelineState:
        """Run log analysis and capture results."""
        print("\n" + "=" * 60)
        print("PHASE 1: LOG ANALYSIS")
        print("=" * 60)

        log_file = state["log_file"]
        print(f"Analyzing log file: {log_file}")

        if progress_callback:
            progress_callback(20, "Running log analysis...")

        # Run log analysis (agent should not print its own phase headers)
        analysis_result = log_agent.analyze(log_file)

        # Store results in state
        state["log_analysis_result"] = analysis_result

        if progress_callback:
            progress_callback(40, "Log analysis completed")

        print(
            f"\nLog Analysis Assessment: {analysis_result.get('overall_assessment', 'UNKNOWN')}"
        )
        print(f"Abnormal Events: {len(analysis_result.get('abnormal_events', []))}")

        return state

    def run_retrieval_with_context(state: PipelineState) -> PipelineState:
        """Transform log analysis results and run retrieval supervisor."""
        print("\n" + "=" * 60)
        print("PHASE 2: THREAT INTELLIGENCE RETRIEVAL")
        print("=" * 60)

        # Get log analysis results
        log_analysis_result = state["log_analysis_result"]
        assessment = log_analysis_result.get("overall_assessment", "UNKNOWN")

        # Create retrieval query based on log analysis
        query = create_retrieval_query(log_analysis_result, state.get("query"))

        print(f"Generated retrieval query based on {assessment} assessment")
        print("\nStarting retrieval supervisor with log analysis context...\n")

        if progress_callback:
            progress_callback(50, "Running threat intelligence retrieval...")

        # Run retrieval supervisor with trace=True to show terminal output
        retrieval_result = retrieval_supervisor.invoke(
            query=query,
            log_analysis_report=log_analysis_result,
            context=state.get("query"),
            trace=False,  # This shows the agent conversations in terminal
        )

        if progress_callback:
            progress_callback(70, "Threat intelligence retrieval completed")

        # Store retrieval results in state
        state["retrieval_result"] = retrieval_result

        return state

    def run_response_analysis(state: PipelineState) -> PipelineState:
        """Run response agent to create Event ID → MITRE technique mappings."""
        print("\n" + "=" * 60)
        print("PHASE 3: RESPONSE CORRELATION ANALYSIS")
        print("=" * 60)
        print("Creating Event ID → MITRE technique mappings...")

        if progress_callback:
            progress_callback(80, "Running response correlation analysis...")

        # Run response agent analysis (agent should not print its own phase headers)
        response_analysis, markdown_report = response_agent.analyze_and_map(
            log_analysis_result=state["log_analysis_result"],
            retrieval_result=state["retrieval_result"],
            log_file=state["log_file"],
            tactic=state.get("tactic"),
        )

        if progress_callback:
            progress_callback(90, "Response analysis completed")

        # Store response analysis in state
        state["response_analysis"] = response_analysis

        # Store the markdown report in state
        state["markdown_report"] = markdown_report

        # The output path is already saved by analyze_and_map
        print(f"Analysis complete! Results saved to final_response folder.")

        print(f"\n" + "=" * 60)
        print("PIPELINE COMPLETED")
        print("=" * 60)

        return state

    # Create the workflow
    workflow = StateGraph(PipelineState)

    # Add nodes
    workflow.add_node("log_analysis", run_log_analysis)
    workflow.add_node("retrieval", run_retrieval_with_context)
    workflow.add_node("response", run_response_analysis)

    # Define flow
    workflow.set_entry_point("log_analysis")
    workflow.add_edge("log_analysis", "retrieval")
    workflow.add_edge("retrieval", "response")
    workflow.add_edge("response", END)

    return workflow.compile(name="simple_integrated_pipeline")


def create_retrieval_query(
    log_analysis_result: Dict[str, Any], user_query: str = None
) -> str:
    """Transform log analysis results into a retrieval query."""
    assessment = log_analysis_result.get("overall_assessment", "UNKNOWN")
    analysis_summary = log_analysis_result.get("analysis_summary", "")
    abnormal_events = log_analysis_result.get("abnormal_events", [])

    if assessment == "NORMAL" and not user_query:
        return "Analyze this normal log activity and provide baseline threat intelligence for monitoring purposes."

    query_parts = [
        "Analyze the detected security anomalies and provide comprehensive threat intelligence.",
        "",
        f"Log Analysis Assessment: {assessment}",
        f"Summary: {analysis_summary}",
        "",
    ]

    if abnormal_events:
        query_parts.append("Detected Anomalies:")
        for i, event in enumerate(abnormal_events[:5], 1):  # Top 5 events
            event_desc = event.get("event_description", "Unknown event")
            severity = event.get("severity", "Unknown")
            event_id = event.get("event_id", "N/A")

            query_parts.append(f"{i}. Event {event_id} [{severity}]: {event_desc}")

        query_parts.append("")

    # Add intelligence requirements
    query_parts.extend(
        [
            "Intelligence Requirements:",
            "1. Map findings to relevant MITRE ATT&CK techniques and tactics",
            "2. Provide threat actor attribution and campaign intelligence",
            "3. Generate actionable IOCs and detection recommendations",
            "4. Assess threat severity and recommend response actions",
        ]
    )

    if user_query:
        query_parts.extend(["", f"Additional Context: {user_query}"])

    return "\n".join(query_parts)


def analyze_log_file(
    log_file: str,
    query: str = None,
    tactic: str = None,
    model_name: str = "google_genai:gemini-2.0-flash",
    temperature: float = 0.1,
    max_log_analysis_iterations: int = 2,
    max_retrieval_iterations: int = 2,
    log_agent_output_dir: str = "analysis",
    response_agent_output_dir: str = "final_response",
    progress_callback=None,
):
    """
    Analyze a single log file through the integrated pipeline.

    Args:
        log_file: Path to the log file to analyze
        query: Optional user query for additional context
        tactic: Optional tactic name for organizing output
        model_name: Name of the model to use (e.g., "google_genai:gemini-2.0-flash", "groq:gpt-oss-120b", "groq:llama-3.1-8b-instant")
        temperature: Temperature for model generation
        max_log_analysis_iterations: Maximum number of iterations for the log analysis agent
        max_retrieval_iterations: Maximum number of iterations for the retrieval supervisor
        log_agent_output_dir: Directory to save log agent output
        response_agent_output_dir: Directory to save response agent output
    """
    if not os.path.exists(log_file):
        print(f"Error: Log file not found: {log_file}")
        return

    print(f"Starting integrated pipeline analysis...")
    print(f"Log file: {log_file}")
    print(f"Model: {model_name}")
    if tactic:
        print(f"Tactic: {tactic}")
    print(f"User query: {query or 'None'}")

    # Create pipeline with specified model
    pipeline = create_simple_pipeline(
        model_name=model_name,
        temperature=temperature,
        max_log_analysis_iterations=max_log_analysis_iterations,
        max_retrieval_iterations=max_retrieval_iterations,
        log_agent_output_dir=log_agent_output_dir,
        response_agent_output_dir=response_agent_output_dir,
        progress_callback=progress_callback,
    )

    # Initialize state
    initial_state = {
        "log_file": log_file,
        "log_analysis_result": {},
        "retrieval_result": {},
        "response_analysis": {},
        "query": query or "",
        "tactic": tactic or "",
        "markdown_report": "",
    }

    # Run pipeline
    start_time = time.time()

    if progress_callback:
        progress_callback(10, "Initializing pipeline...")

    final_state = pipeline.invoke(initial_state)
    end_time = time.time()

    if progress_callback:
        progress_callback(100, "Analysis complete!")

    print(f"\nTotal execution time: {end_time - start_time:.2f} seconds")
    print("Analysis complete!")
    return final_state


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print(
            "Usage: python simple_pipeline.py <log_file> [query] [--model MODEL_NAME]"
        )
        print("\nExamples:")
        print("  python simple_pipeline.py sample_log.json")
        print(
            "  python simple_pipeline.py sample_log.json 'Focus on credential access attacks'"
        )
        print("  python simple_pipeline.py sample_log.json --model groq:gpt-oss-120b")
        print("\nAvailable models:")
        print("  - google_genai:gemini-2.0-flash")
        print("  - google_genai:gemini-1.5-flash")
        print("  - groq:gpt-oss-120b")
        print("  - groq:gpt-oss-20b")
        print("  - groq:llama-3.1-8b-instant")
        print("  - groq:llama-3.3-70b-versatile")
        sys.exit(1)

    log_file = sys.argv[1]
    query = None
    # FIX: Use full model name format consistently
    model_name = "google_genai:gemini-2.0-flash"  # Changed from "gemini-2.0-flash"
    temperature = 0.1
    max_log_analysis_iterations = 2
    max_retrieval_iterations = 2
    log_agent_output_dir = "analysis"
    response_agent_output_dir = "final_response"

    # Parse arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--model" and i + 1 < len(sys.argv):
            model_name = sys.argv[i + 1]
            i += 2
        else:
            query = sys.argv[i]
            i += 1

    # Setup environment
    load_dotenv()

    # Run analysis
    try:
        final_state = analyze_log_file(
            log_file,
            query,
            tactic=None,
            model_name=model_name,
            temperature=temperature,
            max_log_analysis_iterations=max_log_analysis_iterations,
            max_retrieval_iterations=max_retrieval_iterations,
            log_agent_output_dir=log_agent_output_dir,
            response_agent_output_dir=response_agent_output_dir,
        )
        print(final_state["markdown_report"])
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
