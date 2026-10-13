"""
Evaluation (Stage 7, extended in Stage 9): run the full pipeline on every log in
data/ground_truth.json and compare the predicted technique IDs with the expected ones.

Scores are given two ways:
  strict  - exact technique ID match
  lenient - parent or sub-technique also counts (T1059 <-> T1059.007)
For each log it also scores retrieval alone (top-1 and top-3 per event), so the report
can show what Mistral adds. Results are printed and saved to MongoDB "evaluations".

Splits: "dev" logs were used while building the system; "test" logs are held out.

Run: python evaluate.py              (full pipeline with Mistral)
     python evaluate.py --no-llm     (retrieval only, fast)
     python evaluate.py --no-save    (don't write to MongoDB)
     python evaluate.py --log mshta_javascript.json   (one log)
"""

import argparse
import json

import config
import db
from agents.graph import run_investigation
from tools.metrics import (is_related, lenient_precision_recall_f1, match_counts, precision_recall_f1,
                           scores_from_counts)
from tools.retriever import predicted_ids

METHODS = (("baseline_top1", "retrieval top-1"), ("baseline_top3", "retrieval top-3"), ("metrics", "mistral"))


def evaluate_log(log_name: str, entry: dict, use_llm: bool, save: bool) -> tuple[dict, dict]:
    """Run one log through the pipeline and score it. Returns (result, pipeline state)."""
    state = run_investigation(config.LOGS_DIR / log_name, save_to_db=save, use_llm=use_llm)
    # Score unique technique IDs per log: an ID found by several events counts once
    expected = set(entry["techniques"])
    predicted = {
        "metrics": set(state.get("predicted_ids", [])),
        "baseline_top1": set(predicted_ids(state["suspicious"], top_n=1)),
        "baseline_top3": set(predicted_ids(state["suspicious"], top_n=3)),
    }
    result = {
        "log_file": log_name,
        "split": entry.get("split", "dev"),
        "method": f"{config.LLM_MODEL} + retrieval" if use_llm else "retrieval top-1",
        "expected_ids": sorted(expected),
        "predicted_ids": sorted(predicted["metrics"]),
        "suspicious_count": len(state.get("suspicious", [])),
        "grounding_removed": state.get("grounding_removed", []),
        "llm_seconds": state.get("llm_seconds", 0),
        "investigation_id": state.get("investigation_id", ""),
        "errors": state.get("errors", []),
    }
    for key, ids in predicted.items():
        result[key] = precision_recall_f1(ids, expected)
        result[f"{key}_lenient"] = lenient_precision_recall_f1(ids, expected)
    if save:
        try:
            db.save_evaluation(result)
        except RuntimeError as e:
            result["errors"].append(f"Evaluation not saved: {e}")
    return result, state


def _predicted(r: dict, key: str) -> set[str]:
    if key == "metrics":
        return set(r["predicted_ids"])
    return set(r[key]["true_positives"]) | set(r[key]["false_positives"])


def overall(results: list[dict], key: str, lenient: bool = False) -> dict:
    """Micro-average over logs: add up per-log counts of unique techniques, then score."""
    totals = [0, 0, 0, 0]
    for r in results:
        counts = match_counts(_predicted(r, key), set(r["expected_ids"]), lenient=lenient)
        totals = [t + c for t, c in zip(totals, counts)]
    return scores_from_counts(*totals)


def _predicted_by_any(r: dict) -> set[str]:
    """Every technique ID predicted for this log by any method."""
    return set().union(*(_predicted(r, key) for key, _ in METHODS))


def diagnose_misses(results: list[dict], states: dict[str, dict]) -> None:
    """For ground-truth techniques no method predicted (not even leniently), show what retrieval saw."""
    from tools.knowledge_base import get_collection, search  # only needed here

    print("\n" + "=" * 92 + "\nMissed by every method (strict)")
    found_any = False
    for r in results:
        state = states[r["log_file"]]
        for tid in sorted(set(r["expected_ids"]) - _predicted_by_any(r)):
            found_any = True
            try:
                name = get_collection().get(ids=[tid])["metadatas"][0]["name"]
            except (RuntimeError, IndexError):
                name = "?"
            lenient_hit = sorted(p for p in _predicted_by_any(r) if is_related(p, tid))
            print(f"\n{tid} {name}  (log: {r['log_file']}, {r['split']})"
                  + (f"  [lenient match: {', '.join(lenient_hit)}]" if lenient_hit else ""))
            if not state["suspicious"]:
                print("  no suspicious events were flagged in this log")
                continue
            for event in state["suspicious"][:5]:
                print(f"  [{event['event_id']}] {event['sentence'][:110]}")
                print("     top-5: " + ", ".join(f"{m['technique_id']} {m['score']:.2f}" for m in event["matches"][:5]))
            family = tid.split(".")[0]
            related = sorted({m["technique_id"] for e in state["suspicious"] for m in e["matches"]
                              if m["technique_id"] != tid and m["technique_id"].split(".")[0] == family})
            print(f"  parent/sub-technique of {family} retrieved: {', '.join(related) or 'none'}")
            ranks = []
            for event in state["suspicious"]:
                ids = [m["technique_id"] for m in search(event["sentence"], k=50)]
                if tid in ids:
                    ranks.append((ids.index(tid) + 1, event["event_id"]))
            best = min(ranks) if ranks else None
            print(f"  best rank in top-50: {f'#{best[0]} ({best[1]})' if best else 'not in top 50'}")
    if not found_any:
        print("  none")


def print_table(results: list[dict], use_llm: bool) -> None:
    print("\n" + "=" * 92)
    print(f"{'Split':<6} {'Logs':>4} {'IDs':>4}  {'Method':<16} | {'strict P':>8} {'R':>5} {'F1':>5} "
          f"| {'lenient P':>9} {'R':>5} {'F1':>5}")
    for split in ("dev", "test", "all"):
        subset = [r for r in results if split == "all" or r["split"] == split]
        if not subset:
            continue
        n_ids = sum(len(r["expected_ids"]) for r in subset)
        for i, (key, label) in enumerate(METHODS):
            if key == "metrics" and not use_llm:
                continue
            s, l = overall(subset, key), overall(subset, key, lenient=True)
            counts = f"{len(subset):>4} {n_ids:>4}" if i == 0 else " " * 9
            print(f"{split:<6} {counts}  {label:<16} | {s['precision']:>8.2f} {s['recall']:>5.2f} {s['f1']:>5.2f} "
                  f"| {l['precision']:>9.2f} {l['recall']:>5.2f} {l['f1']:>5.2f}")
    silent = [r["log_file"] for r in results if r["suspicious_count"] == 0]
    if silent:
        print(f"\nLogs with no suspicious events flagged: {', '.join(silent)}")


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

    results, states = [], {}
    for log_name, entry in truth.items():
        print(f"Evaluating {log_name} ({entry.get('split', 'dev')}) ...", flush=True)
        r, states[log_name] = evaluate_log(log_name, entry, use_llm=not args.no_llm, save=not args.no_save)
        results.append(r)
        m, ml = r["metrics"], r["metrics_lenient"]
        print(f"  predicted {r['predicted_ids']} | expected {r['expected_ids']} | {r['suspicious_count']} suspicious")
        print(f"  strict F1={m['f1']:.2f} (P={m['precision']:.2f} R={m['recall']:.2f}) | lenient F1={ml['f1']:.2f} "
              f"| missed {m['missed']} | wrong {m['false_positives']} "
              f"| removed by grounding: {len(r['grounding_removed'])} | LLM {r['llm_seconds']}s")
        for error in r["errors"]:
            print(f"  [!] {error}")

    print_table(results, use_llm=not args.no_llm)
    diagnose_misses(results, states)
    if not args.no_save:
        print("\nSaved to MongoDB: investigations + evaluations.")


if __name__ == "__main__":
    main()
