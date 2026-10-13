"""
Sysmon ingest and normalization (Stage 4).

Reads a Mordor/OTRF log (one JSON event per line), keeps the useful Sysmon events
and turns each into a plain-English sentence for retrieval, e.g.
  "sc.exe (Service Control Manager Configuration Tool) was started by cmd.exe
   with command line: sc config Fax binPath= powershell.exe -noexit ..."

Design notes (see check_kb.py):
- Sentences describe the action in words; raw command lines with long paths retrieve badly,
  so Windows paths inside command lines are shortened to the file name.
- ATT&CK IDs that appear inside the log itself (e.g. Atomic Red Team's 'T1543.003 Test')
  are masked, so retrieval cannot "cheat" by reading the answer.
- Every sentence keeps the source event ID(s) = "<file>#L<line number>" for traceability.
- Identical sentences are merged into one (with a count and all source IDs) to cut noise.
"""

import base64
import json
import re
from pathlib import Path

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# Sysmon event IDs we keep (process, network, file, registry, DNS)
EVENT_TYPES = {
    1: "process_creation",
    3: "network_connection",
    11: "file_created",
    12: "registry_key",
    13: "registry_value_set",
    14: "registry_key_renamed",
    22: "dns_query",
}

# Plain-English meaning of a few well-known Windows registry locations.
# This explains *what the location is*; it is not an ATT&CK mapping.
REGISTRY_HINTS = [
    (re.compile(r"\\CurrentControlSet\\Services\\([^\\]+)\\ImagePath$", re.I),
     "the executable path of Windows service '{0}'"),
    (re.compile(r"\\CurrentControlSet\\Services\\([^\\]+)\\Start$", re.I),
     "the start type of Windows service '{0}'"),
    (re.compile(r"\\CurrentVersion\\Run(Once)?\\", re.I),
     "a Run key that starts programs automatically at logon"),
    (re.compile(r"\\Environment\\UserInitMprLogonScript$", re.I),
     "a logon script that runs when the user logs on"),
]

DETAIL_FIELDS = ("TargetObject", "Details", "TargetFilename", "DestinationIp", "DestinationPort",
                 "DestinationHostname", "QueryName")

ATTACK_ID_PATTERN = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b", re.I)
WINDOWS_PATH_PATTERN = re.compile(r"[A-Za-z]:\\(?:[^\\\s\"']+\\)+([^\\\s\"']+)")
URL_PATTERN = re.compile(r"\b(?:https?|ftp)://([^/\s\"']+)", re.I)
ENCODED_PS_PATTERN = re.compile(r"\s-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", re.I)


def _name(path: str) -> str:
    """C:\\Windows\\System32\\cmd.exe -> cmd.exe"""
    return str(path or "").split("\\")[-1] or "unknown process"


def mask_attack_ids(text: str) -> str:
    """Hide ATT&CK IDs written inside the log (answer leak), e.g. 'T1543.003 Test'."""
    return ATTACK_ID_PATTERN.sub("[ID removed]", text)


def shorten_paths(text: str) -> str:
    r"""C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -> powershell.exe"""
    return WINDOWS_PATH_PATTERN.sub(r"\1", text)


def decode_encoded_powershell(command_line: str) -> str | None:
    """If the command uses 'powershell -enc <base64>', return the decoded script (idea from Cyber-Agent's decoder tool)."""
    match = ENCODED_PS_PATTERN.search(command_line)
    if not match:
        return None
    try:
        return base64.b64decode(match.group(1)).decode("utf-16-le", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return None


def clean_command(command_line: str, limit: int = 200) -> str:
    """Normalize a command line for a sentence: short paths, single spaces, masked IDs, length limit."""
    text = shorten_paths(str(command_line))
    text = re.sub(r"[A-Za-z0-9+/=]{40,}", "[base64 data]", text)  # long blobs carry no meaning for retrieval
    text = re.sub(r"\s+", " ", text).replace('\\"', '"').strip()
    return mask_attack_ids(text)[:limit]


def _registry_hint(target: str) -> str:
    for pattern, template in REGISTRY_HINTS:
        match = pattern.search(target)
        if match:
            return " (" + template.format(*match.groups()) + ")"
    return ""


def to_sentence(event: dict) -> str:
    """Turn one Sysmon event into a readable sentence."""
    eid = event.get("EventID")
    image = _name(event.get("Image"))

    if eid == 1:
        description = event.get("Description")
        what = f"{image} ({description})" if description and description != "-" else image
        sentence = (f"{what} was started by {_name(event.get('ParentImage'))} "
                    f"with command line: {clean_command(event.get('CommandLine', ''))}")
        # State facts about remote addresses in words (the raw URL alone retrieves poorly)
        command_line = str(event.get("CommandLine", ""))
        url = URL_PATTERN.search(command_line)
        if url:
            local = " and a local file path" if WINDOWS_PATH_PATTERN.search(command_line) else ""
            sentence += f". The command line contains a web address ({url.group(1)}){local}"
        decoded = decode_encoded_powershell(command_line)
        if decoded:
            sentence += f". Encoded PowerShell command decodes to: {clean_command(decoded)}"
        return sentence

    if eid == 3:
        host = event.get("DestinationHostname")
        host = f" ({host})" if host and host != "-" else ""
        return (f"{image} made a {event.get('Protocol', '')} network connection to "
                f"{event.get('DestinationIp')}:{event.get('DestinationPort')}{host}")

    if eid == 11:
        return f"{image} created file {shorten_paths(str(event.get('TargetFilename', '')))}"

    if eid in (12, 13, 14):
        target = str(event.get("TargetObject", ""))
        hint = _registry_hint(target)
        if eid == 13:
            return f"{image} set registry value {target}{hint} to: {clean_command(event.get('Details', ''))}"
        action = {"CreateKey": "created", "DeleteKey": "deleted", "DeleteValue": "deleted",
                  "RenameKey": "renamed"}.get(event.get("EventType"), "changed")
        return f"{image} {action} registry key {target}{hint}"

    if eid == 22:
        return f"{image} looked up the domain name {event.get('QueryName')}"

    return f"{image} generated Sysmon event {eid}"


def load_events(path: Path) -> list[tuple[int, dict]]:
    """Read a JSON-lines log. Returns (line_number, event) pairs; unreadable lines are skipped."""
    events = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append((line_no, json.loads(line)))
                except json.JSONDecodeError:
                    pass
    except OSError as e:
        raise RuntimeError(f"Could not read log file {path}: {e}") from e
    return events


def parse_log(path: str | Path) -> tuple[list[dict], list[dict]]:
    """
    Parse a log file.

    Returns:
      raw_events  - the kept Sysmon events as-is, each with its 'event_id' (for MongoDB 'logs')
      normalized  - one entry per unique sentence, in time order, with all source event IDs
    """
    path = Path(path)
    raw_events, normalized, by_sentence = [], [], {}

    for line_no, event in load_events(path):
        eid = event.get("EventID")
        if event.get("Channel") != SYSMON_CHANNEL or eid not in EVENT_TYPES:
            continue

        event_id = f"{path.name}#L{line_no}"
        raw_events.append({"event_id": event_id, "log_file": path.name, "raw": event})

        sentence = to_sentence(event)
        if sentence in by_sentence:  # same thing happened again: just record the extra source ID
            by_sentence[sentence]["source_event_ids"].append(event_id)
            by_sentence[sentence]["count"] += 1
            continue

        entry = {
            "event_id": event_id,              # first occurrence
            "source_event_ids": [event_id],    # every raw event behind this sentence
            "count": 1,
            "log_file": path.name,
            "sysmon_event_id": eid,
            "event_type": EVENT_TYPES[eid],
            "timestamp": event.get("UtcTime", ""),
            "host": event.get("Hostname", ""),
            "process": _name(event.get("Image")),
            "parent_process": _name(event.get("ParentImage")) if eid == 1 else "",
            "command_line": mask_attack_ids(str(event.get("CommandLine", ""))) if eid == 1 else "",
            "user": event.get("User", ""),
            # Event-specific fields the Detect step looks at (IDs masked here too)
            "raw_fields": {k: mask_attack_ids(str(event[k])) for k in DETAIL_FIELDS if k in event},
            "sentence": sentence,
        }
        by_sentence[sentence] = entry
        normalized.append(entry)

    normalized.sort(key=lambda e: e["timestamp"])
    return raw_events, normalized
