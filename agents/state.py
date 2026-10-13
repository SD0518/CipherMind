"""Shared state passed between the LangGraph nodes."""

from typing import Callable, TypedDict


class InvestigationState(TypedDict, total=False):
    log_path: str            # input: path to the uploaded log file
    log_file: str            # file name, used in event IDs and reports
    log_id: str              # content fingerprint, links MongoDB documents to this log
    save_to_db: bool         # input: False skips MongoDB writes (e.g. quick tests)
    use_llm: bool            # input: False skips Mistral (retrieval-only report)
    progress_callback: Callable  # input (optional): called with (done, total, message) during the report
    raw_events: list[dict]   # kept Sysmon events as-is (ingest)
    events: list[dict]       # normalized sentences with source event IDs (ingest)
    suspicious: list[dict]   # flagged events with reasons (detect), then + matches (classify)
    findings: list[dict]     # events Mistral mapped to techniques, with explanations (report)
    predicted_ids: list[str] # all accepted technique IDs for this log (report)
    summary: str             # Mistral's narrative + recommendations (report)
    report: str              # final Markdown report (report)
    grounding_removed: list[str]  # cited IDs dropped because they were not retrieved (report)
    llm_seconds: float       # time spent in Mistral calls (report)
    investigation_id: str    # MongoDB id of the saved investigation ("" if not saved)
    errors: list[str]        # problems collected along the way (shown to the user)
