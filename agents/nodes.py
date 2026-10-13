"""
LangGraph nodes: ingest -> detect -> classify -> report.

Each node takes the state and returns only the keys it updates.
Errors are collected in state["errors"] instead of crashing the whole run.
"""

from pathlib import Path

from agents.state import InvestigationState
from tools.detector import detect
from tools.retriever import retrieve
from tools.sysmon_parser import parse_log


def ingest_node(state: InvestigationState) -> dict:
    """Parse the log file into raw events and normalized sentences."""
    path = Path(state["log_path"])
    try:
        raw_events, events = parse_log(path)
    except RuntimeError as e:
        return {"log_file": path.name, "raw_events": [], "events": [],
                "errors": state.get("errors", []) + [f"Ingest failed: {e}"]}
    return {"log_file": path.name, "raw_events": raw_events, "events": events}


def detect_node(state: InvestigationState) -> dict:
    """Keep only suspicious events (each gets its 'reasons')."""
    return {"suspicious": detect(state.get("events", []))}


def classify_node(state: InvestigationState) -> dict:
    """Retrieve the top ATT&CK techniques for every suspicious event."""
    return {"suspicious": retrieve(state.get("suspicious", []))}


def report_node(state: InvestigationState) -> dict:
    """
    Placeholder report (Stage 6): lists suspicious events and their top matches.
    Stage 7 replaces this with a cited report written by Mistral.
    """
    lines = [f"Investigation of {state.get('log_file', '?')}: "
             f"{len(state.get('suspicious', []))} suspicious of {len(state.get('events', []))} events", ""]
    for event in state.get("suspicious", []):
        lines.append(f"[{event['event_id']}] {event['sentence'][:160]}")
        lines.append(f"    why flagged: {'; '.join(event['reasons'])}")
        for match in event.get("matches", [])[:3]:
            lines.append(f"    {match['score']:.3f}  {match['technique_id']}  {match['name']}")
        lines.append("")
    return {"report": "\n".join(lines)}
