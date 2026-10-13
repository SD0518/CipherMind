"""
Stage 5 check: does the ATT&CK knowledge base return the right techniques?

Each test is a query plus the technique ID we expect to see in the top results.
The log-style queries look like the sentences Stage 4 will produce for our two logs.

Run: python check_kb.py
"""

import config
from tools.knowledge_base import get_collection, search

TESTS = [
    # (query, expected technique ID)
    ("encoded powershell command", "T1059.001"),  # the PLAN.MD "done when" test
    ("bitsadmin.exe launched by cmd.exe with command line: bitsadmin.exe /transfer /Download "
     "/priority Foreground https://raw.githubusercontent.com/... C:\\Users\\wardog\\Desktop\\file.md", "T1197"),
    ("bitsadmin.exe downloads a file from a remote URL to the local disk", "T1105"),
    # The raw "sc config Fax binPath= C:\...\powershell.exe ..." command line ranked T1543.003
    # outside the top 5 (the long powershell path dominates). Describing the action in words
    # ranks it #1, so Stage 4 sentences must say what a command does, not just copy it.
    ("Windows service Fax reconfigured with sc config binPath= pointing to powershell.exe", "T1543.003"),
    ("powershell.exe launched by services.exe with command line: powershell.exe -noexit -c write-host", "T1059.001"),
]


def run_tests() -> bool:
    try:
        print(f"[KB] Collection '{config.CHROMA_COLLECTION}' has {get_collection().count()} techniques\n")
    except RuntimeError as e:
        raise SystemExit(f"[KB] FAILED: {e}")

    passed = 0
    for query, expected in TESTS:
        matches = search(query, k=config.TOP_K)
        ids = [m["technique_id"] for m in matches]
        rank = ids.index(expected) + 1 if expected in ids else None
        status = f"OK (rank {rank})" if rank else "MISS"
        passed += bool(rank)

        print(f"[{status}] expected {expected} | query: {query[:80]}")
        for m in matches:
            mark = "  <--" if m["technique_id"] == expected else ""
            print(f"         {m['score']:.3f}  {m['technique_id']:<10} {m['name']}{mark}")
        print()

    print(f"{passed}/{len(TESTS)} expected techniques found in the top {config.TOP_K}.")
    return passed == len(TESTS)


if __name__ == "__main__":
    run_tests()
