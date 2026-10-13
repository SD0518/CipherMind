"""
CipherMind web app (Stage 8): Gradio UI with tabs Analyze, Retrieval, Report, History.

Run: python app.py      then open http://127.0.0.1:7860

Everything runs locally: Mistral via Ollama, ChromaDB on disk, MongoDB on localhost.
Styling lives in ui_style.css. This file only builds the UI; the pipeline is in agents/ and tools/.
"""

import html
import os
import re
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
NO_SAMPLE = ""  # dropdown value meaning "nothing picked"
EMPTY_RESULTS = ('<div class="cm-empty">Results will appear here.<br>'
                 'Upload a log or choose a sample log, then press <b>Analyze log</b>.</div>')
EMPTY_RETRIEVAL = '<div class="cm-empty">Run an analysis to see the suspicious events and their ATT&amp;CK matches.</div>'
MATCH_HINT = "Match = similarity to the ATT&amp;CK description, not attack severity"
SUMMARY_SENTENCES = 3  # sentences of the Mistral summary shown in the Attack summary box

esc = html.escape


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
    return f'<span class="cm-badge"><span class="cm-dot {state}"></span>{esc(name)} <small>{esc(detail)}</small></span>'


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
    note_html = f'<div class="cm-note">{esc(note)}</div>' if note else ""
    return f'<ul class="cm-steps">{"".join(items)}</ul>{note_html}'


def _match_level(score: float) -> str:
    """Match strength from retrieval similarity (how close the event is to the ATT&CK description)."""
    return "strong" if score >= 0.45 else "moderate" if score >= 0.35 else "weak"


def _technique_evidence(state: dict) -> dict:
    """technique id -> {name, best score, events: [(event_id, sentence)]} from the confirmed findings."""
    techs = {}
    for f in state.get("findings", []):
        for tid in f["technique_ids"]:
            t = techs.setdefault(tid, {"name": f["names"][tid], "score": 0.0, "events": []})
            t["score"] = max(t["score"], f["scores"][tid])
            t["events"].append((f["event_id"], f["sentence"]))
    return dict(sorted(techs.items(), key=lambda x: -x[1]["score"]))  # strongest match first


def _summary_sentences(summary: str, n: int = SUMMARY_SENTENCES) -> str:
    """First n plain sentences of the Mistral summary (no headers, numbering, citations or recommendations)."""
    text = re.split(r"recommended actions", summary, flags=re.I)[0]
    lines = [re.sub(r"^\s*(\d+[.)]|[-*•])\s*", "", line).strip() for line in text.splitlines()]
    text = " ".join(line for line in lines if line and not line.endswith(":"))
    text = re.sub(r"\s*\[[^\]]*#L\d+[^\]]*\]", "", text)          # drop [file.json#L12] citations
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    return " ".join(sentences[:n]).strip()


def _attack_summary_html(state: dict) -> str:
    techs = _technique_evidence(state)
    text = _summary_sentences(state.get("summary", ""))
    parts = ['<div class="cm-summary"><div class="t">Attack summary</div>']
    if text:
        parts.append(f"<p>{esc(text)}</p>")
    if techs:
        tid, t = next(iter(techs.items()))
        parts.append(f'<p class="key">Most important finding: <b class="cm-id">{esc(tid)}</b> {esc(t["name"])}</p>')
    else:
        parts.append('<p class="key">No ATT&amp;CK technique was confirmed for this log.</p>')
    return "".join(parts) + "</div>"


def _stats_html(state: dict, seconds: float) -> str:
    stats = [
        (len(state.get("raw_events", [])), "Events parsed"),
        (len(state.get("suspicious", [])), "Suspicious events"),
        (len(state.get("predicted_ids", [])), "Techniques found"),
        (f"{seconds:.0f} s", "Analysis time"),
    ]
    cards = "".join(f'<div class="cm-stat"><div class="v">{v}</div><div class="l">{l}</div></div>' for v, l in stats)
    return f'<div class="cm-stats">{cards}</div>'


def _events_list(events: list[tuple[str, str]]) -> str:
    rows = "".join(f'<li>{esc(sentence[:220])}<span class="cm-id">{esc(event_id)}</span></li>'
                   for event_id, sentence in events)
    return f'<ul class="cm-evlist">{rows}</ul>'


def _techniques_html(state: dict) -> str:
    """One card per identified technique (strongest match first), with expandable evidence."""
    techs = _technique_evidence(state)
    head = f'<div class="cm-heading">Techniques identified</div><div class="cm-hint">{MATCH_HINT}</div>'
    if not techs:
        return head + '<div class="cm-empty">No technique confirmed.</div>'
    cards = []
    for tid, t in techs.items():
        level = _match_level(t["score"])
        n = len(t["events"])
        cards.append(
            f'<div class="cm-tech {level}"><div class="id cm-id">{esc(tid)}</div>'
            f'<div class="name">{esc(t["name"])}</div>'
            f'<div class="meta"><span>similarity {t["score"]:.2f}</span>'
            f'<span class="cm-level {level}">{level.capitalize()} match</span></div>'
            f'<details><summary>{n} event{"s" if n > 1 else ""}</summary>{_events_list(t["events"])}</details></div>')
    return head + f'<div class="cm-techs">{"".join(cards)}</div>'


def _checks_html(state: dict, metrics: dict | None) -> str:
    """Plain-language checks: grounding, score, saved, warnings."""
    items = []
    removed = len(state.get("grounding_removed", []))
    if removed == 0:
        items.append(("ok", "All cited techniques verified against retrieval"))
    else:
        items.append(("warn", f"Grounding check: {removed} unsupported technique{'s' if removed > 1 else ''} "
                              f"removed by the verifier"))
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
    rows = "".join(f'<li><span class="cm-dot {s}"></span>{esc(t)}</li>' for s, t in items)
    return f'<ul class="cm-checks">{rows}</ul>'


# ---------- Retrieval tab: event cards ----------

def _pattern(event: dict) -> str:
    """Sentence with variable parts (IPs, numbers, GUIDs, looked-up domains) blanked, to group look-alike events."""
    s = event["sentence"]
    if event.get("event_type") == "dns_query":
        s = re.sub(r"domain name \S+", "domain name <domain>", s)
    s = re.sub(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?", "<guid>", s, flags=re.I)
    s = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "<ip>", s)
    s = re.sub(r"\d+", "#", s)
    return f"{event.get('event_type', '')}|{event.get('process', '')}|{s}"


def _group_events(suspicious: list[dict]) -> list[list[dict]]:
    """Look-alike events in one group; groups sorted by their strongest match (highest first)."""
    groups = {}
    for event in suspicious:
        groups.setdefault(_pattern(event), []).append(event)
    best = lambda evs: max((m["score"] for e in evs for m in e.get("matches", [])), default=0.0)  # noqa: E731
    ordered = [sorted(evs, key=lambda e: -max((m["score"] for m in e.get("matches", [])), default=0.0))
               for evs in groups.values()]
    return sorted(ordered, key=lambda evs: -best(evs))


def _event_card(events: list[dict]) -> str:
    lead = events[0]  # the member with the strongest match represents the group
    chosen = {tid for e in events for tid in e.get("llm", {}).get("accepted_ids", [])}
    count = (f'<span class="cm-count">×{len(events)} events</span>' if len(events) > 1
             else f'<span class="eid cm-id">{esc(lead["event_id"])}</span>')
    tags = "".join(f'<span class="cm-tag">{esc(r)}</span>' for r in lead.get("reasons", []))

    rows = []
    for m in lead.get("matches", [])[:5]:
        is_chosen = m["technique_id"] in chosen
        label = '<span class="chosen-label">Mistral\'s choice</span>' if is_chosen else ""
        width = max(4, min(100, round(m["score"] * 100)))
        rows.append(
            f'<li class="{"chosen" if is_chosen else ""}"><span class="cm-id">{esc(m["technique_id"])}</span>'
            f'<span class="nm" title="{esc(m["name"])}">{esc(m["name"])}{label}</span>'
            f'<span class="cm-bar"><span class="track"><span class="fill" style="width:{width}%"></span></span>'
            f'{m["score"]:.2f}</span></li>')

    more = ""
    if len(events) > 1:
        more = (f'<details><summary>Show all {len(events)} event IDs</summary>'
                f'{_events_list([(e["event_id"], e["sentence"]) for e in events])}</details>')
    return (f'<div class="cm-ev"><div class="top"><div class="sentence">{esc(lead["sentence"][:300])}</div>{count}</div>'
            f'<div class="cm-tags">{tags}</div><ul class="cm-matches">{"".join(rows)}</ul>{more}</div>')


def _retrieval_html(suspicious: list[dict]) -> str:
    if not suspicious:
        return EMPTY_RETRIEVAL
    cards = "".join(_event_card(group) for group in _group_events(suspicious))
    return f'<div class="cm-hint">{MATCH_HINT}</div><div class="cm-events">{cards}</div>'


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
    Yields: steps, attack summary, stats, techniques, checks, full-report button,
            retrieval cards, full report, report file.
    """
    hidden = gr.update(visible=False)
    path = uploaded or (str(config.LOGS_DIR / sample) if sample else None)
    if not path:
        yield (_steps_html([], note="Upload a log or choose a sample log first."),
               "", EMPTY_RESULTS, "", "", hidden, EMPTY_RETRIEVAL, "", None)
        return

    def on_progress(done: int, total: int, message: str) -> None:
        progress((done, total), desc=message)

    start = time.time()
    done_steps, state = [], {}
    yield _steps_html([], active="ingest"), "", EMPTY_RESULTS, "", "", hidden, EMPTY_RETRIEVAL, "", None
    try:
        for node, state in stream_investigation(path, use_llm=use_llm, progress_callback=on_progress):
            done_steps.append(node)
            next_step = next((n for n, _, _ in STEPS if n not in done_steps), None)
            note = "Mistral is mapping each event (about 15-20 s per event)..." if next_step == "report" and use_llm else ""
            yield (_steps_html(done_steps, active=next_step, note=note), "", EMPTY_RESULTS, "", "",
                   hidden, _retrieval_html(state.get("suspicious", [])), "", None)
    except Exception as e:  # keep the UI alive and show what went wrong
        failed = next((n for n, _, _ in STEPS if n not in done_steps), None)
        yield (_steps_html(done_steps, error=failed, note=f"Analysis failed: {e}"),
               "", EMPTY_RESULTS, "", "", hidden, EMPTY_RETRIEVAL, "", None)
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

    yield (_steps_html(done_steps, note=f"Done: {state.get('log_file', '')}"),
           _attack_summary_html(state),
           _stats_html(state, seconds),
           _techniques_html(state),
           _checks_html(state, metrics),
           gr.update(visible=True),
           _retrieval_html(state.get("suspicious", [])),
           state.get("report", ""),
           _save_report_file(state))


# ---------- History ----------

def _history_table(items: list[dict]) -> str:
    if not items:
        return '<div class="cm-empty">No investigations yet.</div>'
    rows = []
    for item in items:
        when = item["created_at"].replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M")
        log = item.get("log_file", "")
        techs = ", ".join(item.get("predicted_ids", [])) or "-"
        f1 = item.get("metrics", {}).get("f1")
        f1_cell = (f'<td class="num">{f1:.2f}</td>' if f1 is not None
                   else '<td class="na" title="no ground truth for this log">-</td>')
        rows.append(f'<tr><td>{when}</td><td title="{esc(log)}">{esc(log)}</td>'
                    f'<td class="num">{item.get("suspicious_count", "")}</td>'
                    f'<td class="cm-id" title="{esc(techs)}">{esc(techs)}</td>{f1_cell}</tr>')
    return ('<div class="cm-table-wrap"><table class="cm-table"><colgroup>'
            '<col style="width:17%"><col style="width:27%"><col style="width:11%"><col style="width:37%">'
            '<col style="width:8%"></colgroup><thead><tr><th>When (UTC)</th><th>Log file</th><th>Suspicious</th>'
            '<th>Techniques</th><th>F1</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>")


def load_history(show_all: bool = False):
    """Investigations from MongoDB (latest run per log, or every run), for the table and the dropdown."""
    try:
        items = db.get_history(limit=300)
    except RuntimeError as e:
        return f'<div class="cm-empty">MongoDB unavailable: {esc(str(e))}</div>', gr.update(choices=[], value=None), ""
    if not show_all:  # history is newest first, so the first run seen per log is the latest
        latest = {}
        for item in items:
            latest.setdefault(item.get("log_file", ""), item)
        items = list(latest.values())
    choices = [(f"{item['created_at'].replace(tzinfo=timezone.utc).strftime('%Y-%m-%d %H:%M')} | "
                f"{item.get('log_file', '')}", item["_id"]) for item in items]
    info = f"{len(items)} {'runs' if show_all else 'logs (latest run each)'}"
    return _history_table(items), gr.update(choices=choices, value=None), info


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
    primary_hue="blue", neutral_hue="slate",
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
                    summary_html = gr.HTML()
                    stats_html = gr.HTML(EMPTY_RESULTS)
                    techniques_html = gr.HTML()
                    checks_html = gr.HTML()
                    full_report_btn = gr.Button("Full report →", variant="secondary", size="sm", visible=False)

        with gr.Tab("Retrieval", id="retrieval"):
            gr.Markdown("Suspicious events, why they were flagged, and the top ATT&CK techniques retrieved from "
                        "ChromaDB. Mistral may only choose from these; its choice is highlighted.")
            retrieval_html = gr.HTML(EMPTY_RETRIEVAL)

        with gr.Tab("Report", id="report"):
            report_md = gr.Markdown("_Run an analysis to see the report._")
            report_file = gr.File(label="Download report (.md)")

        with gr.Tab("History", id="history"):
            with gr.Row():
                refresh_btn = gr.Button("Refresh", scale=0)
                show_all = gr.Checkbox(value=False, label="Show all runs", scale=0, min_width=160)
                history_info = gr.Markdown()
            history_html = gr.HTML()
            gr.Markdown("#### Open a past report", elem_classes="cm-section")
            pick = gr.Dropdown(choices=[], show_label=False, container=False)
            past_report = gr.Markdown()

    run_btn.click(analyze, inputs=[upload, sample, use_llm],
                  outputs=[steps_html, summary_html, stats_html, techniques_html, checks_html,
                           full_report_btn, retrieval_html, report_md, report_file])
    full_report_btn.click(lambda: gr.Tabs(selected="report"), outputs=tabs)
    refresh_btn.click(load_history, inputs=show_all, outputs=[history_html, pick, history_info])
    show_all.change(load_history, inputs=show_all, outputs=[history_html, pick, history_info])
    pick.change(open_report, inputs=pick, outputs=past_report)
    demo.load(service_status, outputs=status_bar)
    demo.load(load_history, inputs=show_all, outputs=[history_html, pick, history_info])


if __name__ == "__main__":
    threading.Thread(target=warm_up, daemon=True).start()
    demo.queue().launch(server_name="127.0.0.1", server_port=7860, inbrowser=True)
