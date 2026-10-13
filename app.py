"""
CipherMind web app (Stage 8): Gradio UI with tabs Analyze, Retrieval, Report, History.

Run: python app.py      then open http://127.0.0.1:7860

Everything runs locally: Mistral via Ollama, ChromaDB on disk, MongoDB on localhost.
"""

import os
import tempfile
import threading
from datetime import timezone
from pathlib import Path

os.environ.setdefault("GRADIO_ANALYTICS_ENABLED", "False")  # fully local: no usage pings

import gradio as gr  # noqa: E402

import config  # noqa: E402
import db  # noqa: E402
from agents.graph import stream_investigation  # noqa: E402
from tools.knowledge_base import get_collection, load_embedder  # noqa: E402
from tools.metrics import precision_recall_f1  # noqa: E402
from tools.report_writer import warm_up_llm  # noqa: E402

STEP_LABELS = {
    "ingest": "1/4 Ingest: parsed the log into readable sentences",
    "detect": "2/4 Detect: flagged suspicious events",
    "classify": "3/4 Classify: retrieved ATT&CK techniques from ChromaDB",
    "report": "4/4 Report: cited report written and saved",
}
RETRIEVAL_HEADERS = ["Event ID", "Time (UTC)", "Event", "Why flagged", "Top-5 retrieved (similarity)", "Mistral chose"]
HISTORY_HEADERS = ["When (UTC)", "Log file", "Suspicious", "Techniques", "F1"]


# ---------- startup ----------

def load_ground_truth() -> dict:
    """Map log content fingerprint -> ground-truth entry, so uploads of known logs can be scored."""
    import json
    try:
        with open(config.GROUND_TRUTH_JSON, encoding="utf-8") as f:
            truth = json.load(f)
    except (OSError, ValueError):
        return {}
    by_id = {}
    for name, entry in truth.items():
        path = config.LOGS_DIR / name
        if not name.startswith("_") and path.exists():
            by_id[db.log_id_for(path)] = {**entry, "log_file": name}
    return by_id


GROUND_TRUTH = load_ground_truth()


def warm_up() -> None:
    """Load the embedding model, ChromaDB and Mistral in the background so the first run is fast."""
    try:
        load_embedder()
        get_collection()
    except RuntimeError as e:
        print(f"[Startup] {e}")
    if warm_up_llm():
        print("[Startup] Mistral loaded")


def service_status() -> str:
    """One-line health check shown at the top of the page."""
    parts = []
    try:
        parts.append(f"✅ ChromaDB: {get_collection().count()} ATT&CK techniques")
    except RuntimeError:
        parts.append("❌ ChromaDB: run `python build_kb.py`")
    parts.append("✅ MongoDB" if db.ping() else "⚠️ MongoDB offline (results will not be saved)")
    parts.append(f"🧠 LLM: Ollama `{config.LLM_MODEL}` (local)")
    return " &nbsp;|&nbsp; ".join(parts)


# ---------- Analyze ----------

def _retrieval_rows(suspicious: list[dict]) -> list[list]:
    rows = []
    for e in suspicious:
        matches = "; ".join(f"{m['technique_id']} {m['name']} ({m['score']:.2f})" for m in e.get("matches", []))
        chose = ", ".join(e.get("llm", {}).get("accepted_ids", [])) or ("-" if "llm" in e else "")
        rows.append([e["event_id"], e["timestamp"], e["sentence"][:220], "; ".join(e["reasons"]), matches, chose])
    return rows


def _overview(state: dict, metrics: dict | None) -> str:
    names = {tid: f["names"][tid] for f in state.get("findings", []) for tid in f["technique_ids"]}
    md = [f"### {state.get('log_file', '')}",
          f"- **Events kept:** {len(state.get('events', []))} unique sentences "
          f"from {len(state.get('raw_events', []))} Sysmon events",
          f"- **Suspicious:** {len(state.get('suspicious', []))}",
          f"- **Techniques identified:** "
          + (", ".join(f"`{t}` {names.get(t, '')}" for t in state.get("predicted_ids", [])) or "none"),
          f"- **Grounding check:** {len(state.get('grounding_removed', []))} un-retrieved IDs removed",
          f"- **Mistral time:** {state.get('llm_seconds', 0)} s"]
    if metrics:
        md.append(f"- **Score vs ground truth:** precision {metrics['precision']:.2f}, "
                  f"recall {metrics['recall']:.2f}, **F1 {metrics['f1']:.2f}** "
                  f"(missed: {', '.join(metrics['missed']) or 'none'})")
    else:
        md.append("- **Score:** no ground truth for this log (only known logs in data/ are scored)")
    if state.get("investigation_id"):
        md.append(f"- **Saved to MongoDB:** investigation `{state['investigation_id']}`")
    for error in state.get("errors", []):
        md.append(f"- ⚠️ {error}")
    return "\n".join(md)


def _save_report_file(state: dict) -> str:
    folder = Path(tempfile.gettempdir()) / "ciphermind_reports"
    folder.mkdir(exist_ok=True)
    path = folder / f"{Path(state['log_file']).stem}_report.md"
    path.write_text(state.get("report", ""), encoding="utf-8")
    return str(path)


def analyze(uploaded: str | None, sample: str | None, use_llm: bool, progress=gr.Progress()):
    """Run the pipeline step by step, updating the UI after each step."""
    path = uploaded or (str(config.LOGS_DIR / sample) if sample else None)
    if not path:
        yield "⚠️ Upload a log file or pick a sample log first.", "", [], "", None
        return

    def on_progress(done: int, total: int, message: str) -> None:
        progress((done, total), desc=message)

    done_steps = []
    state = {}
    try:
        for node, state in stream_investigation(path, use_llm=use_llm, progress_callback=on_progress):
            done_steps.append(STEP_LABELS.get(node, node))
            status = "\n".join(f"- ✅ {s}" for s in done_steps)
            if node == "classify" and use_llm:
                status += "\n- ⏳ 4/4 Report: Mistral is mapping each event (about 15-20 s per event)..."
            yield status, "", _retrieval_rows(state.get("suspicious", [])), "", None
    except Exception as e:  # keep the UI alive and show what went wrong
        yield f"❌ Analysis failed: {e}", "", [], "", None
        return

    # Score against ground truth if this is one of the known logs
    metrics = None
    truth = GROUND_TRUTH.get(state.get("log_id", ""))
    if truth:
        metrics = precision_recall_f1(set(state.get("predicted_ids", [])), set(truth["techniques"]))
        if state.get("investigation_id"):
            try:
                db.set_investigation_metrics(state["investigation_id"], metrics)
                db.save_evaluation({"log_file": truth["log_file"], "split": truth.get("split", "dev"),
                                    "method": "app", "investigation_id": state["investigation_id"],
                                    "expected_ids": sorted(truth["techniques"]),
                                    "predicted_ids": state.get("predicted_ids", []), "metrics": metrics})
            except RuntimeError as e:
                state["errors"].append(f"Score not saved: {e}")

    status = "\n".join(f"- ✅ {s}" for s in done_steps) + "\n\n**Done.** See the Retrieval and Report tabs."
    yield (status, _overview(state, metrics), _retrieval_rows(state.get("suspicious", [])),
           state.get("report", ""), _save_report_file(state))


# ---------- History ----------

def load_history():
    """Latest investigations from MongoDB, for the table and the 'open report' dropdown."""
    try:
        items = db.get_history(limit=50)
    except RuntimeError as e:
        return [], gr.update(choices=[], value=None), f"⚠️ {e}"
    rows, choices = [], []
    for item in items:
        when = item["created_at"].replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M")
        f1 = item.get("metrics", {}).get("f1")
        rows.append([when, item.get("log_file", ""), item.get("suspicious_count", ""),
                     ", ".join(item.get("predicted_ids", [])), "" if f1 is None else f"{f1:.2f}"])
        choices.append((f"{when} | {item.get('log_file', '')}", item["_id"]))
    return rows, gr.update(choices=choices, value=None), f"{len(items)} investigations"


def open_report(investigation_id: str | None) -> str:
    if not investigation_id:
        return ""
    try:
        doc = db.get_investigation(investigation_id)
    except RuntimeError as e:
        return f"⚠️ {e}"
    return doc.get("report", "_No report stored._") if doc else "_Not found._"


# ---------- layout ----------

THEME = gr.themes.Soft(
    primary_hue="emerald", neutral_hue="slate",
    font=["ui-sans-serif", "system-ui", "Segoe UI", "sans-serif"],       # local fonts only
    font_mono=["ui-monospace", "Consolas", "monospace"],
)
FORCE_DARK = "() => { document.body.classList.add('dark'); }"
CSS = ".cm-header h1 {margin-bottom: 0} .cm-header p {opacity: .75; margin-top: 4px}"

with gr.Blocks(title="CipherMind", theme=THEME, js=FORCE_DARK, css=CSS, analytics_enabled=False) as demo:
    gr.Markdown("# 🛡️ CipherMind\nLocal RAG assistant for Sysmon log investigation: "
                "MITRE ATT&CK retrieval + Mistral, with cited, traceable findings.", elem_classes="cm-header")
    status_bar = gr.Markdown()

    with gr.Tab("Analyze"):
        with gr.Row():
            with gr.Column(scale=1):
                upload = gr.File(label="Upload a Sysmon log (Mordor JSON lines)", file_types=[".json"], type="filepath")
                sample = gr.Dropdown(choices=sorted(p.name for p in config.LOGS_DIR.glob("*.json")),
                                     label="...or pick a sample log", value=None)
                use_llm = gr.Checkbox(value=True, label="Use Mistral (untick for a fast retrieval-only report)")
                run_btn = gr.Button("Analyze log", variant="primary")
            with gr.Column(scale=2):
                progress_md = gr.Markdown("Pick a log and press **Analyze log**.")
                overview_md = gr.Markdown()

    with gr.Tab("Retrieval"):
        gr.Markdown("Suspicious events, why they were flagged, the top ATT&CK techniques retrieved from "
                    "ChromaDB, and which one Mistral chose (it may only choose from these).")
        retrieval_table = gr.Dataframe(headers=RETRIEVAL_HEADERS, wrap=True, interactive=False)

    with gr.Tab("Report"):
        report_md = gr.Markdown("_Run an analysis to see the report._")
        report_file = gr.File(label="Download report (.md)")

    with gr.Tab("History"):
        with gr.Row():
            refresh_btn = gr.Button("Refresh", scale=0)
            history_info = gr.Markdown()
        history_table = gr.Dataframe(headers=HISTORY_HEADERS, wrap=True, interactive=False)
        pick = gr.Dropdown(label="Open a past report", choices=[])
        past_report = gr.Markdown()

    run_btn.click(analyze, inputs=[upload, sample, use_llm],
                  outputs=[progress_md, overview_md, retrieval_table, report_md, report_file])
    refresh_btn.click(load_history, outputs=[history_table, pick, history_info])
    pick.change(open_report, inputs=pick, outputs=past_report)
    demo.load(service_status, outputs=status_bar)
    demo.load(load_history, outputs=[history_table, pick, history_info])


if __name__ == "__main__":
    threading.Thread(target=warm_up, daemon=True).start()
    demo.queue().launch(server_name="127.0.0.1", server_port=7860, inbrowser=True)
