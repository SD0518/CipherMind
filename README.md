# CipherMind

A **fully local** RAG assistant for investigating Windows Sysmon logs. It maps suspicious activity to
**MITRE ATT&CK** and writes a cited incident report, where every finding links back to the log line it came from.

```
Sysmon log ─► normalize to sentences ─► detect suspicious events ─► ChromaDB retrieval (ATT&CK)
          ─► Mistral (Ollama) picks from retrieved techniques ─► cited report ─► MongoDB ─► precision / recall / F1
```

Final-year project. Built on [Cyber-Agent](https://github.com/minhan6559/Cyber-Agent) by minhan6559 and team
(see [Credits](#credits)).

## Key ideas

- **Local only.** The LLM runs in Ollama (`mistral`), embeddings use `all-MiniLM-L6-v2`, ChromaDB is on disk and
  MongoDB runs on localhost. No cloud APIs are used.
- **Grounded output.** Mistral may only cite techniques that were retrieved for that event. The code
  checks every cited ID and removes any that were not retrieved.
- **Traceable.** Every finding stores its source event ID (`<log file>#L<line>`).
- **No hardcoded ATT&CK mappings.** Detection rules flag suspicious *behaviour* only. Technique mapping
  comes from ChromaDB retrieval.
- **Honest evaluation.** Development logs are kept separate from a held-out test log that nothing was tuned on.

## Setup

Requirements: Python 3.10+, [Ollama](https://ollama.com) and MongoDB (local service or Docker).

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
ollama pull mistral
python build_kb.py          # one time: stores 679 ATT&CK techniques in ./chroma_db (~20 s)
python check_setup.py       # checks Mistral + MongoDB
```

## Run

```powershell
python app.py               # opens http://127.0.0.1:7860
```

| Tab | What it shows |
|---|---|
| **Analyze** | Upload a log (or pick a sample), progress per step, overview and score |
| **Retrieval** | Suspicious events, why they were flagged, top-5 ATT&CK matches, and Mistral's choice |
| **Report** | The cited incident report (downloadable as Markdown) |
| **History** | Past investigations from MongoDB; open any past report |

Untick **Use Mistral** for a fast, retrieval-only report (also the fallback if Ollama has problems).

## Evaluate

```powershell
python evaluate.py          # all logs with Mistral (~5 min), saved to MongoDB
python evaluate.py --no-llm # retrieval only, fast
```

Results (3 Mordor logs; micro-averaged over unique techniques per log):

| Data | Method | Precision | Recall | F1 |
|---|---|---|---|---|
| Dev (2 logs) | retrieval top-1 | 0.40 | 0.50 | 0.44 |
| Dev (2 logs) | **Mistral + retrieval** | **0.50** | **0.75** | **0.60** |
| Test (held out) | retrieval top-1 | 0.33 | 0.50 | 0.40 |
| Test (held out) | **Mistral + retrieval** | 0.33 | 0.50 | 0.40 |

Known limitations: Mistral sometimes maps plain network or DNS events to weak matches. On the held-out log,
T1059.007 (JavaScript) ranks #7 because "mshta" dominates the event text, so it falls outside the candidates.

## Project layout

| Path | Purpose |
|---|---|
| `app.py` | Gradio UI |
| `agents/` | LangGraph flow: ingest → detect → classify → report |
| `tools/sysmon_parser.py` | Sysmon JSON → readable sentences (masks leaked ATT&CK IDs) |
| `tools/detector.py` | Rule-based suspicious-event filter, with reasons |
| `tools/knowledge_base.py`, `tools/retriever.py` | ChromaDB search over ATT&CK |
| `tools/report_writer.py` | Mistral mapping, grounding check, Markdown report |
| `db.py` | MongoDB (`logs`, `investigations`, `evaluations`) |
| `evaluate.py`, `tools/metrics.py` | Precision / recall / F1 vs `data/ground_truth.json` |
| `config.py` | All settings (models, paths, top-k, MongoDB) |
| `check_*.py` | One test script per stage |
| `data/` | Test logs, ground truth, ATT&CK STIX data |

## Credits

- **[Cyber-Agent](https://github.com/minhan6559/Cyber-Agent)** (minhan6559 and team, COS30049): the base project.
  Its original code is kept for reference in `src/` (including its Streamlit app and
  [original README](src/README_cyber_agent.md)), `self_learn/`, `cti_bench/` and `cyber_knowledge_base/`.
  CipherMind's pipeline is new code and does not import it.
- **[MITRE ATT&CK®](https://attack.mitre.org)**: technique data (`enterprise-attack.json`).
- **[OTRF Security-Datasets (Mordor)](https://github.com/OTRF/Security-Datasets)** and
  **[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)**: the attack logs.
