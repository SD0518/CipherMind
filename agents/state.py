"""Shared state passed between the LangGraph nodes."""

from typing import TypedDict


class InvestigationState(TypedDict, total=False):
    log_path: str            # input: path to the uploaded log file
    log_file: str            # file name, used in event IDs and reports
    log_id: str              # content fingerprint, links MongoDB documents to this log
    save_to_db: bool         # input: False skips MongoDB writes (e.g. quick tests)
    raw_events: list[dict]   # kept Sysmon events as-is (ingest)
    events: list[dict]       # normalized sentences with source event IDs (ingest)
    suspicious: list[dict]   # flagged events with reasons (detect), then + matches (classify)
    report: str              # final report text (report)
    errors: list[str]        # problems collected along the way (shown to the user)
