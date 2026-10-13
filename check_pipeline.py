"""
Stage 6 check: run the LangGraph pipeline (ingest -> detect -> classify -> report)
on every log in data/logs/ and score retrieval alone against the ground truth.

The F1 here is "before the LLM": predictions are the top-N retrieved techniques of
each suspicious event. Stage 7 lets Mistral choose among them, which should raise precision.

Run: python check_pipeline.py
"""

import json

import config
from agents.graph import run_investigation
from tools.metrics import precision_recall_f1
from tools.retriever import predicted_ids

TOP_N_SETTINGS = (1, 3, 5)


def main() -> None:
    with open(config.GROUND_TRUTH_JSON, encoding="utf-8") as f:
        truth = json.load(f)

    totals = {n: {"predicted": set(), "expected": set()} for n in TOP_N_SETTINGS}
    for log_path in sorted(config.LOGS_DIR.glob("*.json")):
        # Retrieval only: no Mistral, nothing written to MongoDB
        state = run_investigation(log_path, save_to_db=False, use_llm=False)
        for error in state.get("errors", []):
            print(f"[ERROR] {error}")

        print("=" * 90)
        print(f"Investigation of {log_path.name}: "
              f"{len(state['suspicious'])} suspicious of {len(state['events'])} events\n")
        for event in state["suspicious"]:
            print(f"[{event['event_id']}] {event['sentence'][:160]}")
            print(f"    why flagged: {'; '.join(event['reasons'])}")
            for match in event["matches"][:3]:
                print(f"    {match['score']:.3f}  {match['technique_id']}  {match['name']}")
            print()

        expected = set(truth.get(log_path.name, {}).get("techniques", {}))
        print(f"Retrieval-only score for {log_path.name} (expected {sorted(expected)}):")
        for n in TOP_N_SETTINGS:
            predicted = predicted_ids(state["suspicious"], top_n=n)
            m = precision_recall_f1(predicted, expected)
            print(f"  top-{n}: P={m['precision']:.2f} R={m['recall']:.2f} F1={m['f1']:.2f} "
                  f"| found {m['true_positives']} missed {m['missed']} | {len(predicted)} predicted")
            # prefix IDs with the log name so the overall score counts per-log hits
            totals[n]["predicted"] |= {f"{log_path.name}:{t}" for t in predicted}
            totals[n]["expected"] |= {f"{log_path.name}:{t}" for t in expected}
        print()

    print("=" * 90)
    print("Overall retrieval-only score (all logs):")
    for n in TOP_N_SETTINGS:
        m = precision_recall_f1(totals[n]["predicted"], totals[n]["expected"])
        print(f"  top-{n}: precision {m['precision']:.2f}  recall {m['recall']:.2f}  F1 {m['f1']:.2f}")


if __name__ == "__main__":
    main()
