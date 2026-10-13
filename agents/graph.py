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


def _get_graph():
    global _graph
    if _graph is None:
        _graph = build_graph()
    return _graph


def run_investigation(log_path: str, save_to_db: bool = True, use_llm: bool = True) -> InvestigationState:
    """
    Run the full pipeline on one log file and return the final state.
    save_to_db=False skips MongoDB; use_llm=False skips Mistral (retrieval-only report).
    """
    return _get_graph().invoke({"log_path": str(log_path), "save_to_db": save_to_db,
                                "use_llm": use_llm, "errors": []})


def stream_investigation(log_path: str, save_to_db: bool = True, use_llm: bool = True,
                         progress_callback=None):
    """
    Same pipeline, but yields (node name, state so far) after each step,
    so the UI can show progress: ingest -> detect -> classify -> report.
    """
    state = {"log_path": str(log_path), "save_to_db": save_to_db, "use_llm": use_llm,
             "progress_callback": progress_callback, "errors": []}
    for step in _get_graph().stream(state, stream_mode="updates"):
        for node, update in step.items():
            state.update(update)
            yield node, state
