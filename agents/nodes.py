"""
LangGraph nodes: ingest -> detect -> classify -> report.

Each node takes the state and returns only the keys it updates.
Errors are collected in state["errors"] instead of crashing the whole run.
"""

from pathlib import Path

import config
import db
from agents.state import InvestigationState
from tools.detector import detect
from tools.report_writer import build_report, build_retrieval_report
from tools.retriever import retrieve
from tools.sysmon_parser import parse_log


def ingest_node(state: InvestigationState) -> dict:
    """Parse the log file into raw events and normalized sentences, then save them to MongoDB."""
    path = Path(state["log_path"])
    errors = list(state.get("errors", []))
    try:
        raw_events, events = parse_log(path)
        log_id = db.log_id_for(path)
    except (RuntimeError, OSError) as e:
        return {"log_file": path.name, "raw_events": [], "events": [],
                "errors": errors + [f"Ingest failed: {e}"]}

    # Saving is optional: if MongoDB is down the analysis still runs
    if state.get("save_to_db", True):
        try:
            db.save_logs(log_id, path.name, raw_events, events)
        except RuntimeError as e:
            errors.append(f"Logs not saved to MongoDB: {e}")

    return {"log_file": path.name, "log_id": log_id, "raw_events": raw_events,
            "events": events, "errors": errors}


def detect_node(state: InvestigationState) -> dict:
    """Keep only suspicious events (each gets its 'reasons')."""
    return {"suspicious": detect(state.get("events", []))}


def classify_node(state: InvestigationState) -> dict:
    """Retrieve the top ATT&CK techniques for every suspicious event."""
    return {"suspicious": retrieve(state.get("suspicious", []))}


def report_node(state: InvestigationState) -> dict:
    """
    Mistral maps each suspicious event to its retrieved techniques and writes a cited report.
    The whole investigation is then saved to MongoDB (if available).
    """
    errors = list(state.get("errors", []))
    suspicious = state.get("suspicious", [])
    if state.get("use_llm", True):
        result = build_report(state.get("log_file", "?"), suspicious, state.get("progress_callback"))
    else:  # quick checks / fallback: no Mistral, top retrieved technique per event
        result = build_retrieval_report(state.get("log_file", "?"), suspicious)
    errors += [f"Report: {e}" for e in result["errors"]]

    update = {
        "suspicious": suspicious,  # now includes Mistral's decision per event ("llm")
        "findings": result["findings"],
        "predicted_ids": result["predicted_ids"],
        "summary": result["summary"],
        "report": result["markdown"],
        "grounding_removed": result["grounding_removed"],
        "llm_seconds": result["llm_seconds"],
        "investigation_id": "",
    }

    if state.get("save_to_db", True):
        try:
            update["investigation_id"] = db.save_investigation({
                "log_file": state.get("log_file"),
                "log_id": state.get("log_id"),
                "model": config.LLM_MODEL,
                "event_count": len(state.get("events", [])),
                "suspicious_count": len(suspicious),
                "suspicious_events": suspicious,
                "findings": result["findings"],
                "predicted_ids": result["predicted_ids"],
                "grounding_removed": result["grounding_removed"],
                "summary": result["summary"],
                "report": result["markdown"],
                "llm_seconds": result["llm_seconds"],
                "errors": errors,
            })
        except RuntimeError as e:
            errors.append(f"Investigation not saved to MongoDB: {e}")

    update["errors"] = errors
    return update
