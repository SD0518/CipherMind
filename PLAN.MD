Base project: Cyber-Agent (github.com/minhan6559/Cyber-Agent), already cloned in this folder. Keep attribution in README.
The original Cyber-Agent code stays in src/ and app.py as reference. New CipherMind code goes in top-level agents/, tools/, db.py, config.py, build_kb.py, evaluate.py, data/.
Build order: 5 → 4 → 6 → 3 → 7 → 8 (riskiest first; MongoDB once data shapes are known; slow Mistral tuning last before UI).

Stage 1: Environment setup

Use the existing venv in this folder and install the new packages: langchain-ollama, gradio, pymongo.
Confirm Ollama is running and mistral responds (ollama list, plus one test prompt).
Start MongoDB (Docker or local) and connect with MongoDB Compass.
Create config.py with the model name, paths, MongoDB URI and top-k.
Done when: Mistral answers a test prompt from Python and Compass connects to MongoDB.

Stage 2: Get the data

Copy 1–2 small attack logs from mordor_dataset/datasets/ into data/ (for example encoded PowerShell, or credential dumping with ntdsutil).
Note the known ATT&CK technique IDs for each log in data/ground_truth.json. These are your ground truth.
Copy mitre_data/enterprise-attack.json into data/ (already downloaded, no need to fetch from mitre/cti).
Done when: data/ has the log files, ground_truth.json and the ATT&CK JSON.

Stage 3: MongoDB layer

Create db.py with pymongo and three collections: logs, investigations, evaluations.
Write simple functions: save_logs(), save_investigation(), get_history().
Done when: a test script inserts and reads a document you can see in Compass.

Stage 4: Sysmon ingest and normalization (replaces Cyber-Agent's LLM log analysis step)

Parse the Mordor/Sysmon JSON and keep only useful events (process creation, network connections, registry and file changes).
Reuse ideas from src/agents/log_analysis_agent/tools/ (field reducer, event ID extractor, base64 decoder) where helpful.
Convert each into a readable sentence, e.g. "powershell.exe launched by winword.exe with an encoded command."
Keep the source event ID with every sentence for traceability.
Save the raw and normalized events to MongoDB.
Done when: uploading a log produces a list of clean sentences and they appear in the logs collection.

Stage 5: ATT&CK knowledge base in ChromaDB

Write a one-time build_kb.py: load the ATT&CK JSON, take each technique's ID, name and description, embed it with sentence-transformers all-MiniLM-L6-v2, and store it in ./chroma_db (collection attack_techniques).
Do not reuse cyber_knowledge_base/ (it was built with the gated embeddinggemma model and needs a Hugging Face token).
Done when: querying "encoded powershell command" returns T1059.001 near the top.

Stage 6: Detect and Retriever (replaces Cyber-Agent's Retrieval Supervisor)

Keep a light Detect step so only suspicious events are sent for analysis.
For each suspicious event, query ChromaDB for the top 3–5 techniques along with their similarity scores.
Wire the LangGraph flow: ingest → detect → classify (retrieve) → report.
Done when: the pipeline outputs events with matched techniques and scores.

Stage 7: Cited report and evaluation (replaces Cyber-Agent's Response Agent)

Send the events and retrieved technique descriptions to Mistral via Ollama, and prompt it to explain each mapping and cite technique IDs only from what was retrieved.
Check in code that every cited ID was retrieved for that event; drop any that were not.
Save the full investigation to MongoDB.
Compare the predicted technique IDs to your ground truth, compute precision, recall and F1, and save the result to evaluations.
Done when: one run produces a report, a stored investigation, and a metric score.

Stage 8: UI and demo prep

Build a new Gradio app (replacing the Streamlit app.py) with a dark theme and tabs: Analyze, Retrieval, Report, History.
The History tab lists past investigations from MongoDB.
Update README with CipherMind usage and credit to Cyber-Agent.
Rehearse with your tested logs, pre-build ChromaDB, and record a backup video.
Done when: you can run the 5-minute demo flow start to finish without errors.
