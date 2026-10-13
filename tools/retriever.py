"""
Retriever (Stage 6): for each suspicious event, find the most similar ATT&CK techniques in ChromaDB.

Technique mapping comes only from here - there are no hardcoded event-to-technique rules.
"""

import config
from tools.knowledge_base import search


def retrieve(events: list[dict], k: int = config.TOP_K) -> list[dict]:
    """Add 'matches' (top-k techniques with similarity scores) to each event."""
    results = []
    for event in events:
        try:
            matches = search(event["sentence"], k=k)
        except RuntimeError as e:
            print(f"[Retriever] {event['event_id']}: {e}")
            matches = []
        results.append({**event, "matches": matches})
    return results


def predicted_ids(events: list[dict], top_n: int = 1, min_score: float = 0.0) -> set[str]:
    """
    Technique IDs predicted by retrieval alone (before the LLM):
    the top_n matches of every suspicious event that score at least min_score.
    """
    ids = set()
    for event in events:
        for match in event.get("matches", [])[:top_n]:
            if match["score"] >= min_score:
                ids.add(match["technique_id"])
    return ids
