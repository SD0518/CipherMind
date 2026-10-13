"""
One-time build of the ATT&CK knowledge base in ChromaDB.

Loads every active technique from data/enterprise-attack.json, embeds it with
all-MiniLM-L6-v2 and stores it in ./chroma_db (collection "attack_techniques").
Re-running deletes and rebuilds the collection, so it is safe to run again.

Run: python build_kb.py      (about 1-2 minutes on CPU)
"""

import time

import config
from tools.knowledge_base import embedding_text, get_client, load_embedder, load_techniques


def build() -> None:
    start = time.time()

    techniques = load_techniques()
    print(f"[KB] Loaded {len(techniques)} active techniques from {config.ATTACK_JSON.name}")

    print(f"[KB] Embedding with {config.EMBEDDING_MODEL} ...")
    embedder = load_embedder()
    vectors = embedder.encode(
        [embedding_text(t) for t in techniques],
        normalize_embeddings=True,
        batch_size=64,
        show_progress_bar=True,
    ).tolist()

    client = get_client()
    try:
        client.delete_collection(config.CHROMA_COLLECTION)  # start clean on rebuild
        print("[KB] Removed old collection")
    except Exception:
        pass  # first build: nothing to delete

    try:
        collection = client.create_collection(
            config.CHROMA_COLLECTION,
            metadata={"hnsw:space": "cosine"},  # cosine distance -> similarity = 1 - distance
        )
        collection.add(
            ids=[t["id"] for t in techniques],
            embeddings=vectors,
            # The document is what the LLM reads later: name + full description
            documents=[f"{t['name']}. {t['description']}" for t in techniques],
            metadatas=[
                {"name": t["name"], "tactics": t["tactics"], "platforms": t["platforms"]}
                for t in techniques
            ],
        )
    except Exception as e:
        raise SystemExit(f"[KB] FAILED to write to ChromaDB: {e}")

    print(f"[KB] Stored {collection.count()} techniques in {config.CHROMA_DIR} "
          f"(collection '{config.CHROMA_COLLECTION}') in {time.time() - start:.0f}s")


if __name__ == "__main__":
    build()
