"""
Stage 4 check: parse each log in data/logs/ and show the normalized sentences.

Also checks:
- no ATT&CK ID leaks through into the sentences
- every sentence keeps its source event ID(s)
- whether each ground-truth technique is retrievable from at least one sentence
  (best rank in the knowledge base); this tells us the sentences carry enough meaning

Run: python check_ingest.py            (summary)
     python check_ingest.py --all      (print every sentence)
"""

import json
import sys

import config
from tools.knowledge_base import search
from tools.sysmon_parser import ATTACK_ID_PATTERN, parse_log

SHOW_ALL = "--all" in sys.argv
INTERESTING = {1, 3, 13, 22}  # event types printed in summary mode


def check_log(path, expected_ids: list[str]) -> bool:
    raw, events = parse_log(path)
    print(f"\n=== {path.name}: {len(raw)} useful Sysmon events -> {len(events)} unique sentences")

    ok = True
    leaks = [e for e in events if ATTACK_ID_PATTERN.search(e["sentence"])]
    if leaks:
        print(f"[FAILED] {len(leaks)} sentences still contain an ATT&CK ID")
        ok = False
    if any(not e["source_event_ids"] for e in events):
        print("[FAILED] some sentences have no source event ID")
        ok = False

    for e in events:
        if SHOW_ALL or e["sysmon_event_id"] in INTERESTING:
            times = f" (x{e['count']})" if e["count"] > 1 else ""
            print(f"  {e['event_id']:<32} {e['sentence'][:150]}{times}")

    # Best rank of each expected technique over all sentences
    best = {tid: (None, None) for tid in expected_ids}
    for e in events:
        for rank, match in enumerate(search(e["sentence"], k=config.TOP_K), start=1):
            tid = match["technique_id"]
            if tid in best and (best[tid][0] is None or rank < best[tid][0]):
                best[tid] = (rank, e["event_id"])
    print()
    for tid, (rank, event_id) in best.items():
        if rank:
            print(f"  [OK]   {tid} retrievable: rank {rank} from {event_id}")
        else:
            print(f"  [MISS] {tid} not in the top {config.TOP_K} for any sentence")
            ok = False
    return ok


if __name__ == "__main__":
    with open(config.GROUND_TRUTH_JSON, encoding="utf-8") as f:
        truth = json.load(f)

    results = []
    for log_path in sorted(config.LOGS_DIR.glob("*.json")):
        expected = list(truth.get(log_path.name, {}).get("techniques", {}))
        results.append(check_log(log_path, expected))

    print("\nAll good - Stage 4 sentences are clean and retrievable." if all(results)
          else "\nSome checks failed (see above).")
