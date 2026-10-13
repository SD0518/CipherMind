"""
Cited report (Stage 7): Mistral maps each suspicious event to ATT&CK, then writes a summary.

Grounding, enforced in code (not just asked for in the prompt):
- For each event, Mistral only sees that event's top-N retrieved techniques.
- Any technique ID it cites that was not retrieved for that event is removed and recorded.
- Technique IDs in the final summary must be among the accepted findings; others are removed.
"""

import json
import re
import time

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

import config

TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

EVENT_SYSTEM_PROMPT = (
    "You are a SOC analyst mapping ONE Windows Sysmon event to MITRE ATT&CK techniques.\n"
    "Rules:\n"
    "- Choose ONLY from the candidate techniques listed. Never use any other technique ID.\n"
    "- Choose the ONE technique that best describes what this specific event does.\n"
    "- Add a second technique only if the event clearly shows two different behaviours.\n"
    "- Do not choose a technique just because it is related or possible. An empty list is fine if nothing fits.\n"
    "- A network connection or DNS lookup on its own is usually only supporting context: choose a technique\n"
    "  for it only if the event by itself clearly shows that technique.\n"
    'Answer with JSON only: {"technique_ids": ["..."], "explanation": "1-2 sentences citing the evidence in the event"}'
)

SUMMARY_SYSTEM_PROMPT = (
    "You are a SOC analyst writing a short incident summary from confirmed findings.\n"
    "Rules:\n"
    "- Use ONLY the technique IDs listed in the findings. Never mention any other technique ID.\n"
    "- Refer to evidence by its event ID in square brackets, e.g. [file.json#L12].\n"
    "- Write: 1) a 3-5 sentence description of what the attacker did, in time order;\n"
    "  2) 'Recommended actions:' followed by 3 short bullet points."
)


def _llm(json_mode: bool) -> ChatOllama:
    return ChatOllama(
        model=config.LLM_MODEL,
        base_url=config.OLLAMA_BASE_URL,
        temperature=config.LLM_TEMPERATURE,
        keep_alive=config.OLLAMA_KEEP_ALIVE,
        num_gpu=config.OLLAMA_NUM_GPU,
        format="json" if json_mode else None,
    )


def _event_prompt(event: dict, candidates: list[dict]) -> str:
    lines = [
        f"Event {event['event_id']}: {event['sentence'][:400]}",
        f"Why it was flagged: {'; '.join(event['reasons'])}",
        "",
        "Candidate techniques:",
    ]
    for c in candidates:
        lines.append(f"- {c['technique_id']} {c['name']}: {c['description'][:config.LLM_DESCRIPTION_CHARS]}")
    return "\n".join(lines)


def classify_event(event: dict) -> dict:
    """
    Ask Mistral which candidate techniques this event shows.
    Returns {accepted_ids, rejected_ids (not retrieved = removed), explanation, error}.
    """
    candidates = event.get("matches", [])[:config.LLM_CANDIDATES]
    allowed = {c["technique_id"] for c in candidates}
    result = {"candidates": [c["technique_id"] for c in candidates],
              "accepted_ids": [], "rejected_ids": [], "explanation": "", "error": ""}
    if not candidates:
        result["error"] = "no retrieved candidates"
        return result

    messages = [SystemMessage(EVENT_SYSTEM_PROMPT), HumanMessage(_event_prompt(event, candidates))]
    for attempt in (1, 2):  # retry once if the JSON is broken
        try:
            reply = _llm(json_mode=True).invoke(messages).content
            data = json.loads(reply)
            break
        except json.JSONDecodeError:
            if attempt == 2:
                result["error"] = "Mistral did not return valid JSON"
                return result
        except Exception as e:  # Ollama not running, model missing, GPU error...
            result["error"] = f"Ollama call failed: {e}"
            return result

    cited = data.get("technique_ids", [])
    if isinstance(cited, str):
        cited = [cited]
    for item in cited:
        # Mistral sometimes writes "T1197 BITS Jobs": take just the ID part
        found = TECHNIQUE_ID.findall(str(item).upper())
        tid = found[0] if found else str(item).strip()
        # Grounding check: keep only IDs retrieved for THIS event
        target = result["accepted_ids"] if tid in allowed else result["rejected_ids"]
        if tid not in target:
            target.append(tid)
    # Mistral does not always respect "prefer one": enforce the limit in code (its first choices win)
    result["accepted_ids"] = result["accepted_ids"][:config.LLM_MAX_TECHNIQUES_PER_EVENT]
    result["explanation"] = str(data.get("explanation", "")).strip()
    return result


def write_summary(log_file: str, findings: list[dict]) -> tuple[str, list[str], str]:
    """
    Ask Mistral for a short narrative + recommendations from the accepted findings.
    Returns (summary text, IDs removed by the grounding check, error).
    """
    if not findings:
        return "No ATT&CK techniques were confirmed for this log.", [], ""

    allowed = {tid for f in findings for tid in f["technique_ids"]}
    lines = [f"Log file: {log_file}", "Confirmed findings (time order):"]
    for f in findings:
        names = ", ".join(f"{tid} {f['names'][tid]}" for tid in f["technique_ids"])
        lines.append(f"- [{f['event_id']}] {f['sentence'][:200]} -> {names}. {f['explanation']}")

    try:
        text = _llm(json_mode=False).invoke(
            [SystemMessage(SUMMARY_SYSTEM_PROMPT), HumanMessage("\n".join(lines))]
        ).content.strip()
    except Exception as e:
        return "", [], f"Ollama call failed while writing the summary: {e}"

    removed = sorted({tid for tid in TECHNIQUE_ID.findall(text) if tid not in allowed})
    for tid in removed:  # grounding check on free text
        text = re.sub(rf"\b{re.escape(tid)}\b", "[uncited ID removed]", text)
    return text, removed, ""


def warm_up_llm() -> bool:
    """Load Mistral into memory with a tiny prompt, so the first real analysis is not slowed down."""
    try:
        _llm(json_mode=False).invoke("Reply with OK.")
        return True
    except Exception as e:
        print(f"[Ollama] warm-up failed: {e}")
        return False


def build_report(log_file: str, suspicious: list[dict], on_progress=None) -> dict:
    """
    Run the per-event mapping and the summary. Returns findings, predicted IDs,
    the Markdown report, grounding stats and errors.
    on_progress(done, total, message) is called before each Mistral call (used by the UI).
    """
    start = time.time()
    findings, errors, removed = [], [], []
    total = len(suspicious) + 1  # one call per event + the summary

    for i, event in enumerate(suspicious):
        if on_progress:
            on_progress(i, total, f"Mistral: mapping event {i + 1} of {len(suspicious)} ({event['event_id']})")
        decision = classify_event(event)
        event["llm"] = decision  # keep Mistral's decision with the event (saved to MongoDB)
        if decision["error"]:
            errors.append(f"{event['event_id']}: {decision['error']}")
        removed += [f"{event['event_id']}: {tid}" for tid in decision["rejected_ids"]]
        if decision["accepted_ids"]:
            names = {m["technique_id"]: m["name"] for m in event["matches"]}
            scores = {m["technique_id"]: m["score"] for m in event["matches"]}
            findings.append({
                "event_id": event["event_id"],
                "source_event_ids": event["source_event_ids"],
                "timestamp": event["timestamp"],
                "sentence": event["sentence"],
                "reasons": event["reasons"],
                "technique_ids": decision["accepted_ids"],
                "names": names,
                "scores": {tid: scores[tid] for tid in decision["accepted_ids"]},
                "explanation": decision["explanation"],
            })

    if on_progress:
        on_progress(total - 1, total, "Mistral: writing the incident summary")
    summary, summary_removed, summary_error = write_summary(log_file, findings)
    if summary_error:
        errors.append(summary_error)
    removed += [f"summary: {tid}" for tid in summary_removed]

    predicted = sorted({tid for f in findings for tid in f["technique_ids"]})
    return {
        "findings": findings,
        "predicted_ids": predicted,
        "summary": summary,
        "grounding_removed": removed,
        "llm_seconds": round(time.time() - start, 1),
        "errors": errors,
        "markdown": render_markdown(log_file, suspicious, findings, summary, removed, predicted),
    }


def build_retrieval_report(log_file: str, suspicious: list[dict]) -> dict:
    """
    Report without Mistral: each suspicious event is mapped to its top retrieved technique.
    Used by the quick check scripts and as a fallback when Ollama is unavailable.
    """
    findings = []
    for event in suspicious:
        if not event.get("matches"):
            continue
        top = event["matches"][0]
        event["llm"] = {"candidates": [top["technique_id"]], "accepted_ids": [top["technique_id"]],
                        "rejected_ids": [], "explanation": "", "error": "LLM not used"}
        findings.append({
            "event_id": event["event_id"], "source_event_ids": event["source_event_ids"],
            "timestamp": event["timestamp"], "sentence": event["sentence"], "reasons": event["reasons"],
            "technique_ids": [top["technique_id"]], "names": {top["technique_id"]: top["name"]},
            "scores": {top["technique_id"]: top["score"]},
            "explanation": "Top retrieved technique (retrieval only, no LLM).",
        })
    predicted = sorted({f["technique_ids"][0] for f in findings})
    summary = "Retrieval-only report: Mistral was not used, so mappings are the top ChromaDB match per event."
    return {"findings": findings, "predicted_ids": predicted, "summary": summary, "grounding_removed": [],
            "llm_seconds": 0.0, "errors": [],
            "markdown": render_markdown(log_file, suspicious, findings, summary, [], predicted)}


def render_markdown(log_file, suspicious, findings, summary, removed, predicted) -> str:
    """Readable incident report (shown in the UI and stored in MongoDB)."""
    md = [f"# CipherMind incident report: {log_file}", ""]
    md += ["## Summary", "", summary or "_Summary unavailable (see errors)._", ""]

    md += ["## Techniques identified", ""]
    if predicted:
        md += ["| Technique | Name | Evidence (event IDs) |", "|---|---|---|"]
        for tid in predicted:
            evidence = [f["event_id"] for f in findings if tid in f["technique_ids"]]
            name = next(f["names"][tid] for f in findings if tid in f["technique_ids"])
            md.append(f"| {tid} | {name} | {', '.join(evidence)} |")
    else:
        md.append("_None confirmed._")
    md.append("")

    md += ["## Findings", ""]
    for f in findings:
        cited = ", ".join(f"{tid} {f['names'][tid]} (similarity {f['scores'][tid]:.2f})" for tid in f["technique_ids"])
        md += [f"### [{f['event_id']}] {f['timestamp']}",
               f"- **Event:** {f['sentence'][:300]}",
               f"- **Why flagged:** {'; '.join(f['reasons'])}",
               f"- **Mapped to:** {cited}",
               f"- **Reasoning:** {f['explanation']}",
               f"- **Source events:** {', '.join(f['source_event_ids'][:5])}"
               + (f" (+{len(f['source_event_ids']) - 5} more)" if len(f["source_event_ids"]) > 5 else ""),
               ""]

    no_mapping = [e for e in suspicious if not e.get("llm", {}).get("accepted_ids")]
    if no_mapping:
        md += ["## Suspicious events with no confirmed technique", ""]
        md += [f"- [{e['event_id']}] {e['sentence'][:160]}" for e in no_mapping]
        md.append("")

    md += ["## Grounding check", "",
           f"Technique IDs removed because they were not retrieved for that event: {len(removed)}"
           + (f" ({', '.join(removed)})" if removed else ""), ""]
    return "\n".join(md)
