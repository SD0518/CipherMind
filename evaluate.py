"""
Evaluation (Stage 7): run the full pipeline on every log in data/ground_truth.json and
compare the predicted technique IDs with the expected ones (precision / recall / F1).

For each log it also scores retrieval alone (top-1 and top-3 per event), so the report
can show what Mistral adds. Results are printed and saved to MongoDB "evaluations".

Splits: "dev" logs were used while building the system; "test" logs are held out.

Run: python evaluate.py              (full pipeline with Mistral, ~1-3 min per log)
     python evaluate.py --no-llm     (retrieval only, fast)
     python evaluate.py --no-save    (don't write to MongoDB)
     python evaluate.py --log mshta_javascript.json   (one log)
"""

import argparse
import json

import config
import db
from agents.graph import run_investigation
from tools.metrics import precision_recall_f1
from tools.retriever import predicted_ids


def evaluate_log(log_name: str, entry: dict, use_llm: bool, save: bool) -> dict:
    """Run one log through the pipeline and score it."""
    state = run_investigation(config.LOGS_DIR / log_name, save_to_db=save, use_llm=use_llm)
    expected = set(entry["techniques"])
    result = {
        "log_file": log_name,
        "split": entry.get("split", "dev"),
        "method": f"{config.LLM_MODEL} + retrieval" if use_llm else "retrieval top-1",
        "expected_ids": sorted(expected),
        "predicted_ids": state.get("predicted_ids", []),
        "metrics": precision_recall_f1(set(state.get("predicted_ids", [])), expected),
        "baseline_top1": precision_recall_f1(predicted_ids(state["suspicious"], top_n=1), expected),
        "baseline_top3": precision_recall_f1(predicted_ids(state["suspicious"], top_n=3), expected),
        "grounding_removed": state.get("grounding_removed", []),
        "llm_seconds": state.get("llm_seconds", 0),
        "investigation_id": state.get("investigation_id", ""),
        "errors": state.get("errors", []),
    }
    if save:
        try:
            db.save_evaluation(result)
        except RuntimeError as e:
            result["errors"].append(f"Evaluation not saved: {e}")
    return result


def overall(results: list[dict], key: str) -> dict:
    """Micro-average over logs: count every (log, technique) pair once."""
    predicted, expected = set(), set()
    for r in results:
        if key == "metrics":
            ids = r["predicted_ids"]
        else:  # baselines keep their own predicted set
            ids = r[key]["true_positives"] + r[key]["false_positives"]
        predicted |= {f"{r['log_file']}:{t}" for t in ids}
        expected |= {f"{r['log_file']}:{t}" for t in r["expected_ids"]}
    return precision_recall_f1(predicted, expected)


def main() -> None:
    parser = argparse.ArgumentParser(description="Score CipherMind against data/ground_truth.json")
    parser.add_argument("--no-llm", action="store_true", help="retrieval only (no Mistral)")
    parser.add_argument("--no-save", action="store_true", help="do not write to MongoDB")
    parser.add_argument("--log", help="evaluate only this log file name")
    args = parser.parse_args()

    with open(config.GROUND_TRUTH_JSON, encoding="utf-8") as f:
        truth = {k: v for k, v in json.load(f).items() if not k.startswith("_")}
    if args.log:
        truth = {args.log: truth[args.log]}

    results = []
    for log_name, entry in truth.items():
        print(f"Evaluating {log_name} ({entry.get('split', 'dev')}) ...", flush=True)
        r = evaluate_log(log_name, entry, use_llm=not args.no_llm, save=not args.no_save)
        results.append(r)
        m = r["metrics"]
        print(f"  predicted {r['predicted_ids']} | expected {r['expected_ids']}")
        print(f"  P={m['precision']:.2f} R={m['recall']:.2f} F1={m['f1']:.2f} | missed {m['missed']} "
              f"| wrong {m['false_positives']} | removed by grounding: {len(r['grounding_removed'])} "
              f"| LLM {r['llm_seconds']}s")
        for error in r["errors"]:
            print(f"  [!] {error}")

    print("\n" + "=" * 78)
    print(f"{'Split':<6} {'Method':<26} {'Precision':>9} {'Recall':>7} {'F1':>6}")
    for split in ("dev", "test", "all"):
        subset = [r for r in results if split == "all" or r["split"] == split]
        if not subset:
            continue
        for key, label in (("baseline_top1", "retrieval top-1"), ("baseline_top3", "retrieval top-3"),
                           ("metrics", results[0]["method"])):
            if key == "metrics" and args.no_llm:
                continue
            m = overall(subset, key)
            print(f"{split:<6} {label:<26} {m['precision']:>9.2f} {m['recall']:>7.2f} {m['f1']:>6.2f}")
    if not args.no_save:
        print("\nSaved to MongoDB: investigations + evaluations.")


if __name__ == "__main__":
    main()
