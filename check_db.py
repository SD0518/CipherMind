"""
Stage 3 check: write to and read from all three MongoDB collections.

1. logs            - runs the pipeline on one log (ingest saves its events)
2. investigations  - saves a small test investigation
3. evaluations     - saves a small test evaluation
4. reads them back (count, history) so you can also see them in MongoDB Compass

Test documents are marked "test": true. Remove them with: python check_db.py --cleanup

Run: python check_db.py
"""

import sys

import config
import db
from agents.graph import run_investigation

TEST_LOG = config.LOGS_DIR / "service_mod_fax.json"


def cleanup() -> None:
    """Delete only the documents this script created."""
    database = db.get_db()
    for name in (config.INVESTIGATIONS_COLLECTION, config.EVALUATIONS_COLLECTION):
        deleted = database[name].delete_many({"test": True}).deleted_count
        print(f"[Cleanup] removed {deleted} test documents from '{name}'")


def main() -> bool:
    if not db.ping():
        print(f"[MongoDB] FAILED: not reachable at {config.MONGO_URI}. Is the MongoDB service running?")
        return False
    print(f"[MongoDB] Connected to {config.MONGO_URI}, database '{config.MONGO_DB}'")

    # 1. logs: the ingest step saves every kept event with its sentence
    state = run_investigation(TEST_LOG)
    for error in state.get("errors", []):
        print(f"[Pipeline] {error}")
    stored = db.count_logs(state["log_id"])
    expected = len(state["raw_events"])
    print(f"[logs]           {stored} documents for {TEST_LOG.name} (expected {expected}) "
          f"-> {'OK' if stored == expected else 'MISMATCH'}")

    # 2. investigations
    investigation_id = db.save_investigation({
        "test": True,
        "log_file": state["log_file"],
        "log_id": state["log_id"],
        "event_count": len(state["events"]),
        "suspicious_count": len(state["suspicious"]),
        "predicted_ids": sorted({m["technique_id"] for e in state["suspicious"] for m in e["matches"][:1]}),
        "suspicious_events": state["suspicious"],
        "report": state["report"],
    })
    print(f"[investigations] saved test investigation {investigation_id}")

    # 3. evaluations
    evaluation_id = db.save_evaluation({
        "test": True, "investigation_id": investigation_id, "log_file": state["log_file"],
        "precision": 0.5, "recall": 0.5, "f1": 0.5,
    })
    print(f"[evaluations]    saved test evaluation {evaluation_id}")

    # 4. read back
    history = db.get_history(limit=3)
    found = any(item["_id"] == investigation_id for item in history)
    print(f"[history]        latest {len(history)} investigations read back; test one found -> {'OK' if found else 'MISSING'}")
    print(f"[collections]    {db.list_collections()}")
    return stored == expected and found


if __name__ == "__main__":
    try:
        if "--cleanup" in sys.argv:
            cleanup()
        else:
            ok = main()
            print("\nAll good - Stage 3 MongoDB layer works. Open Compass -> ciphermind to see the documents."
                  if ok else "\nSome checks failed (see above).")
    except RuntimeError as e:
        print(f"[MongoDB] FAILED: {e}")
