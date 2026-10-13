"""
CipherMind web app (Stage 8): Gradio UI with tabs Analyze, Retrieval, Report, History.

Run: python app.py      then open http://127.0.0.1:7860

Everything runs locally: Mistral via Ollama, ChromaDB on disk, MongoDB on localhost.
Styling lives in ui_style.css.
"""

import html
import os
import tempfile
import threading
import time
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

# Pipeline steps shown in the progress list: (node name, label, description)
STEPS = [
    ("ingest", "Ingest", "parse the log into readable sentences"),
    ("detect", "Detect", "flag suspicious events"),
    ("classify", "Classify", "retrieve ATT&CK techniques from ChromaDB"),
    ("report", "Report", "write and verify the cited report"),
]
RETRIEVAL_HEADERS = ["Event ID", "Time (UTC)", "Event", "Why flagged", "Top-5 retrieved (similarity)", "Mistral chose"]
HISTORY_HEADERS = ["When (UTC)", "Log file", "Suspicious", "Techniques", "F1"]
NO_SAMPLE = ""  # dropdown value meaning "nothing picked"
EMPTY_RESULTS = ('<div class="cm-empty">Results will appear here.<br>'
                 'Upload a log or choose a sample log, then press <b>Analyze log</b>.</div>')
PREVIEW_CHARS = 700  # how much of the report summary to show on the Analyze tab


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


def _badge(state: str, name: str, detail: str) -> str:
    return (f'<span class="cm-badge"><span class="cm-dot {state}"></span>{html.escape(name)}'
            f' <small>{html.escape(detail)}</small></span>')


def service_status() -> str:
    """Health badges shown under the title: ChromaDB · MongoDB · Mistral."""
    try:
        chroma = _badge("ok", "ChromaDB", f"{get_collection().count()} techniques")
    except RuntimeError:
        chroma = _badge("bad", "ChromaDB", "run build_kb.py")
    mongo = _badge("ok", "MongoDB", "connected") if db.ping() else _badge("warn", "MongoDB", "offline, not saving")
    mistral = _badge("ok", "Mistral", "local via Ollama")
    return f'<div class="cm-badges">{chroma}{mongo}{mistral}</div>'


# ---------- Analyze: rendering helpers (display only) ----------

def _steps_html(done: list[str], active: str | None = None, error: str | None = None, note: str = "") -> str:
    """The 4-step pipeline list with coloured dots."""
    items = []
    for node, label, description in STEPS:
        state = ("error" if node == error else "done" if node in done
                 else "active" if node == active else "pending")
        items.append(f'<li class="{state}"><span class="cm-dot {state}"></span>'
                     f'<b>{label}</b><span>{description}</span></li>')
    note_html = f'<div class="cm-note">{html.escape(note)}</div>' if note else ""
    return f'<ul class="cm-steps">{"".join(items)}</ul>{note_html}'


def _match_level(score: float) -> str:
    """Colour tier from retrieval similarity (how strongly the event matches the technique)."""
    return "high" if score >= 0.45 else "medium" if score >= 0.35 else "low"


def _stats_html(state: dict, seconds: float) -> str:
    stats = [
        (len(state.get("raw_events", [])), "Events parsed"),
        (len(state.get("suspicious", [])), "Suspicious events"),
        (len(state.get("predicted_ids", [])), "Techniques found"),
        (f"{seconds:.0f} s", "Analysis time"),
    ]
    cards = "".join(f'<div class="cm-stat"><div class="v">{v}</div><div class="l">{l}</div></div>' for v, l in stats)
    return f'<div class="cm-stats">{cards}</div>'


def _techniques_html(state: dict) -> str:
    """One card per identified technique: ID, name, best similarity, match strength."""
    best = {}  # technique id -> (name, best score, evidence count)
    for f in state.get("findings", []):
        for tid in f["technique_ids"]:
            name, score, count = best.get(tid, (f["names"][tid], 0.0, 0))
            best[tid] = (name, max(score, f["scores"][tid]), count + 1)
    if not best:
        return '<div class="cm-heading">Techniques identified</div><div class="cm-empty">No technique confirmed.</div>'

    cards = []
    for tid, (name, score, count) in sorted(best.items(), key=lambda x: -x[1][1]):
        level = _match_level(score)
        cards.append(
            f'<div class="cm-tech {level}"><div class="id">{html.escape(tid)}</div>'
            f'<div class="name">{html.escape(name)}</div>'
            f'<div class="meta"><span>similarity {score:.2f} · {count} event{"s" if count > 1 else ""}</span>'
            f'<span class="cm-level {level}">{level.capitalize()} match</span></div></div>')
    return f'<div class="cm-heading">Techniques identified</div><div class="cm-techs">{"".join(cards)}</div>'


def _checks_html(state: dict, metrics: dict | None) -> str:
    """Plain-language checks: grounding, score, saved, warnings."""
    items = []
    removed = len(state.get("grounding_removed", []))
    if removed == 0:
        items.append(("ok", "All cited techniques verified against retrieval"))
    else:
        items.append(("warn", f"{removed} cited technique(s) removed: not retrieved for that event"))
    if metrics:
        items.append(("ok", f"Score vs ground truth: precision {metrics['precision']:.2f}, "
                            f"recall {metrics['recall']:.2f}, F1 {metrics['f1']:.2f}"
                            + (f" (missed {', '.join(metrics['missed'])})" if metrics["missed"] else "")))
    else:
        items.append(("pending", "Not scored: no ground truth for this log"))
    if state.get("investigation_id"):
        items.append(("ok", "Saved to History"))
    for error in state.get("errors", []):
        items.append(("warn", error))
    rows = "".join(f'<li><span class="cm-dot {s}"></span>{html.escape(t)}</li>' for s, t in items)
    return f'<ul class="cm-checks">{rows}</ul>'


def _summary_preview(state: dict) -> str:
    """First part of the report summary, cut at a line break."""
    summary = state.get("summary", "").strip()
    if len(summary) <= PREVIEW_CHARS:
        return summary
    cut = summary.rfind("\n", 0, PREVIEW_CHARS)
    cut = cut if cut > PREVIEW_CHARS // 2 else summary.rfind(" ", 0, PREVIEW_CHARS)
    return summary[:cut].rstrip() + " ..."


def _retrieval_rows(suspicious: list[dict]) -> list[list]:
    rows = []
    for e in suspicious:
        matches = "; ".join(f"{m['technique_id']} {m['name']} ({m['score']:.2f})" for m in e.get("matches", []))
        chose = ", ".join(e.get("llm", {}).get("accepted_ids", [])) or ("-" if "llm" in e else "")
        rows.append([e["event_id"], e["timestamp"], e["sentence"][:220], "; ".join(e["reasons"]), matches, chose])
    return rows


def _save_report_file(state: dict) -> str:
    folder = Path(tempfile.gettempdir()) / "ciphermind_reports"
    folder.mkdir(exist_ok=True)
    path = folder / f"{Path(state['log_file']).stem}_report.md"
    path.write_text(state.get("report", ""), encoding="utf-8")
    return str(path)


# ---------- Analyze ----------

def analyze(uploaded: str | None, sample: str | None, use_llm: bool, progress=gr.Progress()):
    """
    Run the pipeline step by step, updating the UI after each step.
    Yields: steps, stats, techniques, summary preview, checks, full-report button,
            retrieval table, full report, report file.
    """
    hidden = gr.update(visible=False)
    path = uploaded or (str(config.LOGS_DIR / sample) if sample else None)
    if not path:
        yield (_steps_html([], note="Upload a log or choose a sample log first."),
               EMPTY_RESULTS, "", "", "", hidden, [], "", None)
        return

    def on_progress(done: int, total: int, message: str) -> None:
        progress((done, total), desc=message)

    start = time.time()
    done_steps, state = [], {}
    yield _steps_html([], active="ingest"), EMPTY_RESULTS, "", "", "", hidden, [], "", None
    try:
        for node, state in stream_investigation(path, use_llm=use_llm, progress_callback=on_progress):
            done_steps.append(node)
            next_step = next((n for n, _, _ in STEPS if n not in done_steps), None)
            note = "Mistral is mapping each event (about 15-20 s per event)..." if next_step == "report" and use_llm else ""
            yield (_steps_html(done_steps, active=next_step, note=note), EMPTY_RESULTS, "", "", "",
                   hidden, _retrieval_rows(state.get("suspicious", [])), "", None)
    except Exception as e:  # keep the UI alive and show what went wrong
        failed = next((n for n, _, _ in STEPS if n not in done_steps), None)
        yield (_steps_html(done_steps, error=failed, note=f"Analysis failed: {e}"),
               EMPTY_RESULTS, "", "", "", hidden, [], "", None)
        return
    seconds = time.time() - start

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

    preview = _summary_preview(state)
    yield (_steps_html(done_steps, note=f"Done: {state.get('log_file', '')}"),
           _stats_html(state, seconds),
           _techniques_html(state),
           f"#### Report summary\n\n{preview}" if preview else "",
           _checks_html(state, metrics),
           gr.update(visible=True),
           _retrieval_rows(state.get("suspicious", [])),
           state.get("report", ""),
           _save_report_file(state))


# ---------- History ----------

def load_history():
    """Latest investigations from MongoDB, for the table and the 'open report' dropdown."""
    try:
        items = db.get_history(limit=50)
    except RuntimeError as e:
        return [], gr.update(choices=[], value=None), f"MongoDB unavailable: {e}"
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
        return f"MongoDB unavailable: {e}"
    return doc.get("report", "_No report stored._") if doc else "_Not found._"


# ---------- layout ----------

THEME = gr.themes.Soft(
    primary_hue="emerald", neutral_hue="slate",
    font=["ui-sans-serif", "system-ui", "Segoe UI", "sans-serif"],       # local fonts only
    font_mono=["ui-monospace", "Consolas", "monospace"],
)
FORCE_DARK = "() => { document.body.classList.add('dark'); }"
CSS = (Path(__file__).parent / "ui_style.css").read_text(encoding="utf-8")
SAMPLE_CHOICES = [("Choose a sample log", NO_SAMPLE)] + [
    (p.name, p.name) for p in sorted(config.LOGS_DIR.glob("*.json"))]

with gr.Blocks(title="CipherMind", theme=THEME, js=FORCE_DARK, css=CSS, analytics_enabled=False) as demo:
    gr.Markdown("# CipherMind\nLocal RAG assistant for Sysmon log investigation: "
                "MITRE ATT&CK retrieval + Mistral, with cited, traceable findings.", elem_classes="cm-header")
    status_bar = gr.HTML()

    with gr.Tabs() as tabs:
        with gr.Tab("Analyze", id="analyze"):
            with gr.Row(equal_height=False):
                with gr.Column(scale=2, min_width=300):
                    gr.Markdown("#### Upload a log", elem_classes="cm-section")
                    upload = gr.File(show_label=False, file_types=[".json"], type="filepath", height=130)
                    gr.Markdown("#### Or use a sample log", elem_classes="cm-section")
                    sample = gr.Dropdown(choices=SAMPLE_CHOICES, value=NO_SAMPLE, show_label=False,
                                         container=False)
                    gr.Markdown("#### Options", elem_classes="cm-section")
                    use_llm = gr.Checkbox(value=True, label="AI-written report with Mistral (slower)")
                    run_btn = gr.Button("Analyze log", variant="primary")
                    gr.Markdown("#### Pipeline", elem_classes="cm-section")
                    steps_html = gr.HTML(_steps_html([]))
                with gr.Column(scale=3, min_width=420):
                    stats_html = gr.HTML(EMPTY_RESULTS)
                    techniques_html = gr.HTML()
                    checks_html = gr.HTML()
                    summary_md = gr.Markdown(elem_classes="cm-preview")
                    full_report_btn = gr.Button("Full report →", variant="secondary", size="sm", visible=False)

        with gr.Tab("Retrieval", id="retrieval"):
            gr.Markdown("Suspicious events, why they were flagged, the top ATT&CK techniques retrieved from "
                        "ChromaDB, and which one Mistral chose (it may only choose from these).")
            retrieval_table = gr.Dataframe(headers=RETRIEVAL_HEADERS, wrap=True, interactive=False)

        with gr.Tab("Report", id="report"):
            report_md = gr.Markdown("_Run an analysis to see the report._")
            report_file = gr.File(label="Download report (.md)")

        with gr.Tab("History", id="history"):
            with gr.Row():
                refresh_btn = gr.Button("Refresh", scale=0)
                history_info = gr.Markdown()
            history_table = gr.Dataframe(headers=HISTORY_HEADERS, wrap=True, interactive=False)
            pick = gr.Dropdown(label="Open a past report", choices=[])
            past_report = gr.Markdown()

    run_btn.click(analyze, inputs=[upload, sample, use_llm],
                  outputs=[steps_html, stats_html, techniques_html, summary_md, checks_html,
                           full_report_btn, retrieval_table, report_md, report_file])
    full_report_btn.click(lambda: gr.Tabs(selected="report"), outputs=tabs)
    refresh_btn.click(load_history, outputs=[history_table, pick, history_info])
    pick.change(open_report, inputs=pick, outputs=past_report)
    demo.load(service_status, outputs=status_bar)
    demo.load(load_history, outputs=[history_table, pick, history_info])


if __name__ == "__main__":
    threading.Thread(target=warm_up, daemon=True).start()
    demo.queue().launch(server_name="127.0.0.1", server_port=7860, inbrowser=True)
