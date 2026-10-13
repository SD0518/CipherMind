"""
The CipherMind pipeline as a LangGraph flow: ingest -> detect -> classify -> report.

Usage:
    from agents.graph import run_investigation
    state = run_investigation("data/logs/service_mod_fax.json")
"""

from langgraph.graph import END, START, StateGraph

from agents.nodes import classify_node, detect_node, ingest_node, report_node
from agents.state import InvestigationState


def build_graph():
    """Build and compile the 4-step investigation graph."""
    graph = StateGraph(InvestigationState)
    graph.add_node("ingest", ingest_node)
    graph.add_node("detect", detect_node)
    graph.add_node("classify", classify_node)
    graph.add_node("report", report_node)

    graph.add_edge(START, "ingest")
    graph.add_edge("ingest", "detect")
    graph.add_edge("detect", "classify")
    graph.add_edge("classify", "report")
    graph.add_edge("report", END)
    return graph.compile()


_graph = None


def run_investigation(log_path: str) -> InvestigationState:
    """Run the full pipeline on one log file and return the final state."""
    global _graph
    if _graph is None:
        _graph = build_graph()
    return _graph.invoke({"log_path": str(log_path), "errors": []})
