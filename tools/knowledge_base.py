"""
ATT&CK knowledge base helpers: load techniques from the STIX file, embed them,
and search them in ChromaDB.

Used by build_kb.py (one-time build) and by the retriever (Stage 6).
"""

import json
import re
from pathlib import Path

import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer

import config

# How much of each field goes into the embedding. all-MiniLM-L6-v2 only reads
# the first 256 tokens, so we keep the most useful parts short: the description
# says what the technique is, the detection text names the tools/commands seen in logs.
EMBED_DESCRIPTION_CHARS = 600
EMBED_DETECTION_CHARS = 400

_embedder = None  # loaded once, reused (loading takes a few seconds)


def clean_text(text: str) -> str:
    """Strip ATT&CK markdown: citations, links and <code> tags."""
    text = re.sub(r"\(Citation:[^)]*\)", "", text)          # (Citation: Microsoft BITS)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)     # [BITSAdmin](https://...) -> BITSAdmin
    text = re.sub(r"</?code>", "", text)                     # <code>sc query</code> -> sc query
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _attack_id(obj: dict) -> str | None:
    """Return the technique ID (e.g. T1059.001) from a STIX object."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def load_techniques(attack_json: Path = config.ATTACK_JSON) -> list[dict]:
    """
    Load active (not revoked/deprecated) ATT&CK techniques.

    Sub-techniques get their parent's name prefixed,
    e.g. T1059.001 -> "Command and Scripting Interpreter: PowerShell".
    """
    with open(attack_json, encoding="utf-8") as f:
        objects = json.load(f)["objects"]

    raw = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = _attack_id(obj)
        if tid:
            raw[tid] = obj

    techniques = []
    for tid, obj in sorted(raw.items()):
        name = obj["name"]
        parent = raw.get(tid.split(".")[0])
        if "." in tid and parent:
            name = f"{parent['name']}: {name}"
        techniques.append({
            "id": tid,
            "name": name,
            "description": clean_text(obj.get("description", "")),
            "detection": clean_text(obj.get("x_mitre_detection", "")),
            "tactics": ", ".join(p["phase_name"] for p in obj.get("kill_chain_phases", [])),
            "platforms": ", ".join(obj.get("x_mitre_platforms", [])),
        })
    return techniques


def embedding_text(tech: dict) -> str:
    """The text we embed for a technique (name + start of description + start of detection)."""
    return (
        f"{tech['name']}. {tech['description'][:EMBED_DESCRIPTION_CHARS]} "
        f"Detection: {tech['detection'][:EMBED_DETECTION_CHARS]}"
    )


def load_embedder() -> SentenceTransformer:
    """Load the sentence-transformers model once (downloads ~90 MB on first use)."""
    global _embedder
    if _embedder is None:
        try:
            _embedder = SentenceTransformer(config.EMBEDDING_MODEL)
        except Exception as e:
            raise RuntimeError(f"Could not load embedding model '{config.EMBEDDING_MODEL}': {e}") from e
    return _embedder


def get_client() -> chromadb.ClientAPI:
    """Open the persistent ChromaDB folder."""
    try:
        return chromadb.PersistentClient(
            path=str(config.CHROMA_DIR), settings=Settings(anonymized_telemetry=False)
        )
    except Exception as e:
        raise RuntimeError(f"Could not open ChromaDB at {config.CHROMA_DIR}: {e}") from e


def get_collection() -> chromadb.Collection:
    """Return the existing ATT&CK collection (run build_kb.py first)."""
    try:
        return get_client().get_collection(config.CHROMA_COLLECTION)
    except Exception as e:
        raise RuntimeError(
            f"ChromaDB collection '{config.CHROMA_COLLECTION}' not found. Run: python build_kb.py ({e})"
        ) from e


def search(query: str, k: int = config.TOP_K) -> list[dict]:
    """
    Return the top-k techniques for a text query.

    score = cosine similarity (1.0 = identical meaning, around 0 = unrelated).
    """
    vector = load_embedder().encode([query], normalize_embeddings=True).tolist()
    try:
        result = get_collection().query(query_embeddings=vector, n_results=k)
    except Exception as e:
        raise RuntimeError(f"ChromaDB query failed: {e}") from e

    matches = []
    for tid, meta, doc, dist in zip(
        result["ids"][0], result["metadatas"][0], result["documents"][0], result["distances"][0]
    ):
        matches.append({
            "technique_id": tid,
            "name": meta["name"],
            "score": round(1 - dist, 3),  # cosine distance -> similarity
            "tactics": meta["tactics"],
            "description": doc,
        })
    return matches
