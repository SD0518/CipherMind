"""
Light Detect step (Stage 6): decide which normalized events are suspicious enough
to send for ATT&CK retrieval and the LLM report.

Simple, explainable rules: every flagged event gets human-readable reasons.
The rules describe suspicious *behaviour* (tools, locations, connections);
they never name ATT&CK techniques - technique mapping comes only from ChromaDB.
"""

import ipaddress
import re

from tools.sysmon_parser import ENCODED_PS_PATTERN, URL_PATTERN

# Built-in Windows tools that attackers commonly abuse ("living off the land" binaries)
WATCHED_TOOLS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "sc.exe", "reg.exe",
    "schtasks.exe", "wmic.exe", "net.exe", "net1.exe", "msiexec.exe", "installutil.exe",
    "ntdsutil.exe", "vssadmin.exe", "whoami.exe", "nltest.exe", "curl.exe",
}

# Parents that should rarely start other programs in normal use
SUSPICIOUS_PARENTS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
}

# Registry locations that control what runs automatically
SUSPICIOUS_REGISTRY = [
    (re.compile(r"\\CurrentControlSet\\Services\\[^\\]+\\ImagePath$", re.I), "changes a Windows service's executable path"),
    (re.compile(r"\\CurrentVersion\\Run(Once)?\\", re.I), "writes a Run key (autostart at logon)"),
    (re.compile(r"\\Environment\\UserInitMprLogonScript$", re.I), "sets a user logon script"),
    (re.compile(r"\\Image File Execution Options\\", re.I), "changes Image File Execution Options"),
]

# Script/executable files dropped by a process; known-benign PowerShell startup files are ignored
RISKY_FILE_EXTENSIONS = (".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".exe", ".dll", ".scr")
BENIGN_FILE_MARKERS = ("__PSScriptPolicyTest_",)


def _is_public_ip(ip: str) -> bool:
    """True for internet addresses (not private, loopback, multicast or link-local)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


def reasons_for(event: dict) -> list[str]:
    """Return the reasons this event looks suspicious (empty list = not suspicious)."""
    raw = event.get("raw_fields", {})
    eid = event["sysmon_event_id"]
    process = event["process"].lower()
    reasons = []

    if eid == 1:  # process creation
        command_line = event.get("command_line", "")
        if process in WATCHED_TOOLS:
            reasons.append(f"watched tool {event['process']} was started")
        if event.get("parent_process", "").lower() in SUSPICIOUS_PARENTS:
            reasons.append(f"started from {event['parent_process']}")
        if event.get("parent_process", "").lower() == "services.exe" and process in WATCHED_TOOLS:
            reasons.append("a shell/tool was started directly by the Service Control Manager")
        if URL_PATTERN.search(command_line):
            reasons.append("command line contains a web address")
        if ENCODED_PS_PATTERN.search(command_line):
            reasons.append("command line contains an encoded PowerShell command")

    elif eid in (12, 13, 14):  # registry
        target = raw.get("TargetObject", "")
        for pattern, why in SUSPICIOUS_REGISTRY:
            if pattern.search(target):
                reasons.append(why)

    elif eid == 3:  # network connection
        if _is_public_ip(str(raw.get("DestinationIp", ""))):
            reasons.append(f"outbound connection to public IP {raw.get('DestinationIp')}")

    elif eid == 22:  # DNS query
        name = str(raw.get("QueryName", ""))
        if "." in name and not name.endswith((".local", ".localdomain")):
            reasons.append(f"DNS lookup of external domain {name}")

    elif eid == 11:  # file created
        target = str(raw.get("TargetFilename", ""))
        if target.lower().endswith(RISKY_FILE_EXTENSIONS) and not any(m in target for m in BENIGN_FILE_MARKERS):
            reasons.append("a script or executable file was written to disk")

    return reasons


def detect(events: list[dict]) -> list[dict]:
    """Return only suspicious events, each with a 'reasons' list added."""
    flagged = []
    for event in events:
        reasons = reasons_for(event)
        if reasons:
            flagged.append({**event, "reasons": reasons})
    return flagged
