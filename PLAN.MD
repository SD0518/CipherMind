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


==================== PHASE 2: stronger results + first Semester 2 feature ====================

Build order: 9 → 10 → 11 → 12.
Stage 9 comes first so that Stage 10's improvements are measured on fresh held-out logs.
Stages 11 and 12 are independent of the scores and can swap if time is short.

Honesty rules for all Phase 2 stages (these are what make the results claimable):
- Ground truth for a new log is written and committed BEFORE the pipeline is ever run on it.
- Logs marked "test" are never used to choose settings, prompts or rules. Tune on "dev" only.
- Settings are locked before the final test run. The test set is run once; that number is reported, good or bad.
- Every score is reported strict and lenient, retrieval-only and Mistral, dev and test, side by side.
- The current results (dev F1 0.60, held-out F1 0.40) stay in the report as the Phase 1 baseline.

Stage 9: Expand the evaluation (weight ~7%, most important)

Pick 7–12 more Mordor logs from mordor_dataset/datasets/ (21 unused; prefer small files with process-creation events and a clear Atomic Red Team test in the name).
For each log, read only the attack command(s) and the Atomic test name, then record the expected technique IDs, a one-line attack summary, the source path and the split in data/ground_truth.json. Commit before running anything.
Split: about 4 dev and 8–10 test logs in total. The existing mshta log stays test. cmd_userinitmprlogonscript must be dev (detector/parser rules were written after seeing it).
Add a lenient score to tools/metrics.py and evaluate.py: a prediction also counts if it is the parent or a sub-technique of an expected ID (T1059 ↔ T1059.007). Siblings (T1059.005 vs T1059.007) do not count. Report strict and lenient side by side.
Add per-split tables and the number of logs/techniques to evaluate.py output. Run retrieval-only on all logs once; run Mistral on all logs once with the current locked Phase 1 settings. This is the new baseline.
Logs with no process-creation events (e.g. covenant_ldap, dcsync) may detect nothing; keep them anyway and report it.
Done when: 10–15 logs in data/, ground truth committed before the first run, evaluate.py prints strict + lenient P/R/F1 per split for retrieval top-1, top-3 and Mistral, and the baseline numbers are recorded in Claude.md.

Stage 10: Make Mistral clearly beat retrieval (weight ~5%)

All changes are developed and tuned on dev logs only; the test split is run once at the end.
Show Mistral the top-7 candidates instead of top-3 (config: LLM_CANDIDATES/TOP_K). This is the T1059.007 fix.
Change the per-event prompt to re-rank: Mistral returns each candidate as accept/reject with a one-line reason, then the code keeps accepted IDs (still grounded, still max per event). Store the reasons; show rejected candidates and reasons in the Retrieval tab and the report.
Move the network/DNS problem into Detect instead of the prompt: plain network connections and DNS lookups are no longer sent to Mistral on their own. They are kept as supporting context for nearby flagged process events (same process or within a short time window) and shown in the report, but they cannot produce a technique by themselves.
Re-run the dev split after each change and record the numbers; then lock settings and run the test split once.
Done when: on the held-out test logs, Mistral's strict F1 is higher than retrieval top-1 and top-3 (if it is not, report that honestly with the diagnosis instead of tuning on test).

Stage 11: IOC extraction, first Semester 2 feature (weight ~4%)

New tools/ioc_extractor.py: pull indicators from the kept Sysmon events using fields first and regex as backup:
  IPs (DestinationIp; mark private vs public), domains (QueryName, URLs in command lines), file hashes (Sysmon Hashes field: SHA256/MD5/IMPHASH), suspicious file paths (files written to user-writable or Temp folders with script/executable extensions), URLs.
Each IOC keeps its type, value, the event IDs it came from, and first-seen time; duplicates are merged. Mask ATT&CK IDs as in the parser.
Store IOCs inside each investigation in MongoDB (no new collection needed); add an "Indicators of compromise" section to the Markdown report and an IOC table/cards on the Analyze tab.
Add check_iocs.py: on the dev logs, the expected IOCs (e.g. raw.githubusercontent.com, 151.101.x.x, the bitsadmin download path, the PowerShell hashes) are found, and no private/loopback IPs are reported as public.
Keep the extractor free of external lookups: enrichment (CVE, threat intel) is a later Semester 2 stage built on this output.
Done when: one run shows IOCs in the UI and the report, they are stored with the investigation, and check_iocs.py passes.

Stage 12: Speed and cleanup (weight ~2%)

Skip near-duplicate events before calling Mistral: group flagged events whose sentences differ only by IDs/numbers/GUIDs and share the same process and top candidates; call Mistral once per group and apply the decision to every event in the group (all source event IDs kept).
Code cleanups from the progress report: check_data.py reuses the parser's log loader and SYSMON_CHANNEL; report_writer.py builds a finding in one shared helper.
Re-run evaluate.py and confirm scores are unchanged or explain any difference; record the time per log before and after.
Done when: Mistral time per log is clearly lower (target 30%+ on the Fax log), all check scripts pass, and scores match the locked Stage 10 results.
