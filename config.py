"""
CipherMind configuration.

Every model name, path, database setting and tuning value lives here.
Other files import from this module instead of hardcoding values.
"""

from pathlib import Path

# Project root (the folder this file is in)
BASE_DIR = Path(__file__).resolve().parent

# --- LLM (local, via Ollama) ---
OLLAMA_BASE_URL = "http://localhost:11434"
LLM_MODEL = "mistral"
LLM_TEMPERATURE = 0.1  # low = more consistent, factual reports
# Keep Mistral loaded in memory between calls so the demo avoids the ~30 s reload
OLLAMA_KEEP_ALIVE = "30m"
# GPU layers for Mistral: None = let Ollama decide (GPU + CPU), 0 = CPU only.
# Use 0 if Ollama fails with "CUDA error" (CPU is ~25% slower but always works).
OLLAMA_NUM_GPU = None

# --- Embeddings ---
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

# --- ChromaDB (ATT&CK knowledge base) ---
CHROMA_DIR = BASE_DIR / "chroma_db"
CHROMA_COLLECTION = "attack_techniques"
TOP_K = 5  # techniques retrieved per event
LLM_CANDIDATES = 3  # of those, how many Mistral may choose from (top-3 had recall 1.0 on dev logs)
LLM_MAX_TECHNIQUES_PER_EVENT = 1  # extra IDs Mistral picks for one event are dropped (2 lowered dev precision)
LLM_DESCRIPTION_CHARS = 350  # technique description length shown to Mistral (keeps prompts short)

# --- MongoDB ---
MONGO_URI = "mongodb://localhost:27017"
MONGO_DB = "ciphermind"
MONGO_TIMEOUT_MS = 3000  # fail fast if MongoDB is not running
LOGS_COLLECTION = "logs"
INVESTIGATIONS_COLLECTION = "investigations"
EVALUATIONS_COLLECTION = "evaluations"

# --- Data ---
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = DATA_DIR / "logs"  # Mordor/Sysmon JSON-lines attack logs
ATTACK_JSON = DATA_DIR / "enterprise-attack.json"
GROUND_TRUTH_JSON = DATA_DIR / "ground_truth.json"
