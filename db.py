"""
MongoDB layer (Stage 3). This is the only file that uses pymongo.

Collections (database "ciphermind"):
  logs            one document per kept Sysmon event: raw event + its normalized sentence
  investigations  one document per pipeline run: suspicious events, matches, report
  evaluations     one document per scored run: precision / recall / F1

Every function raises RuntimeError with a clear message if MongoDB is unreachable,
so the pipeline can catch it and carry on without saving (the demo never crashes on the DB).
"""

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.errors import PyMongoError

import config

_client = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def get_db():
    """Connect once (fails fast after MONGO_TIMEOUT_MS) and return the CipherMind database."""
    global _client
    try:
        if _client is None:
            _client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=config.MONGO_TIMEOUT_MS)
            _create_indexes(_client[config.MONGO_DB])
        return _client[config.MONGO_DB]
    except PyMongoError as e:
        _client = None
        raise RuntimeError(f"MongoDB not reachable at {config.MONGO_URI}: {e}") from e


def _create_indexes(db) -> None:
    """Indexes make lookups fast and stop the same event being stored twice."""
    db[config.LOGS_COLLECTION].create_index([("log_id", ASCENDING), ("event_id", ASCENDING)], unique=True)
    db[config.INVESTIGATIONS_COLLECTION].create_index([("created_at", DESCENDING)])
    db[config.EVALUATIONS_COLLECTION].create_index([("created_at", DESCENDING)])


def ping() -> bool:
    """True if MongoDB answers."""
    try:
        get_db().command("ping")
        return True
    except (RuntimeError, PyMongoError):
        return False


def list_collections() -> list[str]:
    """Names of the collections in the CipherMind database."""
    try:
        return sorted(get_db().list_collection_names())
    except PyMongoError as e:
        raise RuntimeError(f"MongoDB not reachable at {config.MONGO_URI}: {e}") from e


def log_id_for(path: str | Path) -> str:
    """Short fingerprint of the file content, so the same log is recognised even if renamed."""
    with open(path, "rb") as f:
        return hashlib.sha1(f.read()).hexdigest()[:12]


def _safe_keys(value):
    """MongoDB field names cannot contain '.' or start with '$'; replace them in raw events."""
    if isinstance(value, dict):
        return {k.replace(".", "_").lstrip("$"): _safe_keys(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_safe_keys(v) for v in value]
    return value


def save_logs(log_id: str, log_file: str, raw_events: list[dict], events: list[dict]) -> int:
    """
    Store every kept raw event with the normalized sentence it belongs to.
    Re-ingesting the same log replaces its old documents. Returns the number stored.
    """
    sentence_of = {}  # raw event_id -> sentence
    for event in events:
        for source_id in event["source_event_ids"]:
            sentence_of[source_id] = event["sentence"]

    docs = [{
        "log_id": log_id,
        "log_file": log_file,
        "event_id": raw["event_id"],
        "sysmon_event_id": raw["raw"].get("EventID"),
        "sentence": sentence_of.get(raw["event_id"], ""),
        "raw": _safe_keys(raw["raw"]),
        "ingested_at": _now(),
    } for raw in raw_events]

    try:
        collection = get_db()[config.LOGS_COLLECTION]
        collection.delete_many({"log_id": log_id})
        if docs:
            collection.insert_many(docs)
        return len(docs)
    except PyMongoError as e:
        raise RuntimeError(f"Could not save logs for {log_file}: {e}") from e


def save_investigation(investigation: dict) -> str:
    """Store one pipeline run. Returns its id as a string."""
    doc = {**_safe_keys(investigation), "created_at": _now()}
    try:
        return str(get_db()[config.INVESTIGATIONS_COLLECTION].insert_one(doc).inserted_id)
    except PyMongoError as e:
        raise RuntimeError(f"Could not save investigation: {e}") from e


def save_evaluation(evaluation: dict) -> str:
    """Store one precision/recall/F1 result. Returns its id as a string."""
    doc = {**evaluation, "created_at": _now()}
    try:
        return str(get_db()[config.EVALUATIONS_COLLECTION].insert_one(doc).inserted_id)
    except PyMongoError as e:
        raise RuntimeError(f"Could not save evaluation: {e}") from e


def get_history(limit: int = 20) -> list[dict]:
    """Latest investigations first, summary fields only (for the History tab)."""
    fields = {"log_file": 1, "log_id": 1, "created_at": 1, "event_count": 1,
              "suspicious_count": 1, "predicted_ids": 1, "metrics": 1}
    try:
        cursor = (get_db()[config.INVESTIGATIONS_COLLECTION]
                  .find({}, fields).sort("created_at", DESCENDING).limit(limit))
        return [{**doc, "_id": str(doc["_id"])} for doc in cursor]
    except PyMongoError as e:
        raise RuntimeError(f"Could not read history: {e}") from e


def count_logs(log_id: str) -> int:
    """How many raw events are stored for a log."""
    try:
        return get_db()[config.LOGS_COLLECTION].count_documents({"log_id": log_id})
    except PyMongoError as e:
        raise RuntimeError(f"Could not count logs: {e}") from e
