---
name: "cyber-assistant"
version: "0.3.0"
last-updated: "2025-09-10"
summary: "LLM-powered cyber assistant implemented as a LangGraph workflow with two collaborating agents: (1) a Mordor Log Analysis Agent for suspicious host activity detection, and (2) a MITRE ATT&CK Retriever Agent that maps findings to techniques and suggests mitigations. The workflow produces complete end-to-end threat & mitigation reports."
---

# Quick summary
- Goal: Just import necessary component to create an End-to-end analysis of Mordor host logs with automatic ATT&CK technique mapping and mitigation recommendations.
- Input: JSONL log files in Mordor format (host events)
- Language: Python 3.11
- Framework: **LangGraph** (multi-agent workflow orchestration)
- Agents:
  1. **Log Analysis Agent** – `src/agents/log_analysis_agent/log_analysis_agent.py`
  2. **MITRE Retriever Agent** – `src/agents/mitre_retriever_agent/mitre_agent.py`
- Workflow entrypoint: `src/cyber_assistant_pipeline.py`
- LLM Integration: Google Gemini (log analysis) + optional OpenAI / Anthropic (for mitigation recommendations)

# Architecture (high-level)
The system is built as a **LangGraph workflow** with two nodes (agents):
1. **Load & Analyze Logs (Log Analysis Agent)** – processes raw Mordor logs and detects suspicious events with LLM-powered prompts
2. **Map & Recommend (MITRE Retriever Agent)** – transforms suspicious events into MITRE ATT&CK techniques and generates recommended mitigations

# Workflow flow:
load_data → detect_suspicious → mitre_mapping → generate_report → END


# Important files & commands
- `src/agents/log_analysis_agent/log_analysis_agent.py` — Suspicious activity detector
- `src/agents/mitre_retriever_agent/mitre_agent.py` — ATT&CK mapping & mitigation generator
- `src/cyber_assistant_pipeline.py` — LangGraph workflow definition & orchestration
- `mordor_dataset_test/` — Sample dataset directory
- `.env` — API keys configuration (Google, OpenAI, etc.)

# Key Features
- **Two-agent LangGraph workflow** (Log Analysis + MITRE Retriever)
- Structured prompt engineering for suspicious event detection & ATT&CK mapping
- Batch processing for large Mordor datasets
- Executive summaries with prioritized mitigations
- Severity classification & confidence scoring
- Flexible LLM backend support (Google Gemini, OpenAI, Anthropic)

# Known limitations / TODOs
- Requires valid LLM API keys (Google Gemini, OpenAI, etc.)
- Consider adding local LLM integration for air-gapped environments
- Improve real-time streaming of LangGraph node progress
