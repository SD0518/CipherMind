"""
Stage 2 check: confirms the data/ folder is complete and consistent.

- every log file loads and contains Sysmon events
- every log has a ground-truth entry (and the other way round)
- every ground-truth technique ID exists in enterprise-attack.json and is not deprecated
- shows the attack commands found in each log (Sysmon Event ID 1 = process creation)

Run: python check_data.py
"""

import json
from collections import Counter
from pathlib import Path

import config

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def load_log(path: Path) -> list[dict]:
    """Load a Mordor log (one JSON event per line). Bad lines are skipped."""
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def load_attack_ids() -> dict[str, dict]:
    """Return {technique_id: {name, deprecated}} from the ATT&CK STIX file."""
    with open(config.ATTACK_JSON, encoding="utf-8") as f:
        bundle = json.load(f)
    techniques = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                techniques[ref["external_id"]] = {
                    "name": obj.get("name", ""),
                    "deprecated": bool(obj.get("x_mitre_deprecated") or obj.get("revoked")),
                }
    return techniques


def check_files() -> bool:
    """Make sure the expected data files and folders exist."""
    ok = True
    for path in (config.ATTACK_JSON, config.GROUND_TRUTH_JSON, config.LOGS_DIR):
        if path.exists():
            print(f"[Files] OK       {path.relative_to(config.BASE_DIR)}")
        else:
            print(f"[Files] MISSING  {path.relative_to(config.BASE_DIR)}")
            ok = False
    return ok


def check_logs(ground_truth: dict) -> bool:
    """Load each log, count Sysmon events, show attack commands, match against ground truth."""
    ok = True
    log_files = sorted(p.name for p in config.LOGS_DIR.glob("*.json"))
    expected = sorted(k for k in ground_truth if not k.startswith("_"))

    for name in set(log_files) - set(expected):
        print(f"[Logs] WARNING  {name} has no entry in ground_truth.json")
        ok = False
    for name in set(expected) - set(log_files):
        print(f"[Logs] MISSING  {name} is in ground_truth.json but not in data/logs/")
        ok = False

    for name in log_files:
        events = load_log(config.LOGS_DIR / name)
        sysmon = [e for e in events if e.get("Channel") == SYSMON_CHANNEL]
        ids = Counter(e.get("EventID") for e in sysmon)
        print(f"\n[Logs] {name}: {len(events)} events, {len(sysmon)} Sysmon")
        print(f"       Sysmon event IDs: {dict(ids.most_common(8))}")
        if not sysmon:
            print("       FAILED: no Sysmon events found")
            ok = False

        # Event ID 1 = process creation; this is where the attack commands show up
        for e in sysmon:
            if e.get("EventID") == 1:
                parent = str(e.get("ParentImage", "")).split("\\")[-1]
                print(f"       cmd ({parent}): {str(e.get('CommandLine', ''))[:110]}")
    return ok


def check_ground_truth(ground_truth: dict, attack: dict) -> bool:
    """Every expected technique ID must exist in ATT&CK and not be deprecated."""
    ok = True
    print()
    for log_name, entry in ground_truth.items():
        if log_name.startswith("_"):
            continue
        for tid in entry["techniques"]:
            info = attack.get(tid)
            if info is None:
                print(f"[Truth] FAILED  {log_name}: {tid} not found in ATT&CK")
                ok = False
            elif info["deprecated"]:
                print(f"[Truth] FAILED  {log_name}: {tid} ({info['name']}) is deprecated")
                ok = False
            else:
                print(f"[Truth] OK      {log_name}: {tid} = {info['name']}")
    return ok


if __name__ == "__main__":
    try:
        files_ok = check_files()
        if not files_ok:
            raise SystemExit("\nData files missing - re-run Stage 2.")

        with open(config.GROUND_TRUTH_JSON, encoding="utf-8") as f:
            truth = json.load(f)
        attack_ids = load_attack_ids()
        print(f"[ATT&CK] Loaded {len(attack_ids)} techniques")

        logs_ok = check_logs(truth)
        truth_ok = check_ground_truth(truth, attack_ids)
    except (OSError, json.JSONDecodeError) as e:
        raise SystemExit(f"\nFAILED to read data files: {e}")

    print("\nAll good - Stage 2 data is ready." if logs_ok and truth_ok else "\nSome checks failed (see above).")
