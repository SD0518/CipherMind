"""
Stage 1 check: confirms Mistral (Ollama) and MongoDB are reachable from Python.

Run: python check_setup.py
"""

import time

from langchain_ollama import ChatOllama

import config
import db


def check_ollama() -> bool:
    """Send one short prompt to Mistral and print the reply and timing."""
    print(f"[Ollama] Asking '{config.LLM_MODEL}' a test question...")
    try:
        llm = ChatOllama(
            model=config.LLM_MODEL,
            base_url=config.OLLAMA_BASE_URL,
            temperature=config.LLM_TEMPERATURE,
            keep_alive=config.OLLAMA_KEEP_ALIVE,
            num_gpu=config.OLLAMA_NUM_GPU,
        )
        start = time.time()
        reply = llm.invoke("Reply with exactly one short sentence: what is Sysmon?")
        print(f"[Ollama] OK in {time.time() - start:.1f}s -> {reply.content.strip()}")
        return True
    except Exception as e:
        print(f"[Ollama] FAILED: {e}")
        if "CUDA" in str(e):
            print("         GPU error: restart Ollama (tray icon -> Quit, then reopen) or the PC,")
            print("         or set OLLAMA_NUM_GPU = 0 in config.py to run on CPU only.")
        else:
            print("         Is Ollama running? Try 'ollama list' and 'ollama pull mistral'.")
        return False


def check_mongo() -> bool:
    """Ping MongoDB and list the collections in the CipherMind database."""
    print(f"[MongoDB] Connecting to {config.MONGO_URI} ...")
    try:
        collections = db.list_collections()
        print(f"[MongoDB] OK. Database '{config.MONGO_DB}' collections: {collections or '(none yet)'}")
        return True
    except RuntimeError as e:
        print(f"[MongoDB] FAILED: {e}")
        print("          Is the MongoDB service running? Check Windows Services or 'mongosh'.")
        return False


if __name__ == "__main__":
    ollama_ok = check_ollama()
    mongo_ok = check_mongo()
    print("\nAll good - Stage 1 setup works." if ollama_ok and mongo_ok else "\nSome checks failed (see above).")
