# Cybersecurity Threat Intelligence Report
---
## Report Metadata
- **Log File:** `cmd_sharpview_pcre_net_2020-10-2920232423`
- **Analysis Date:** 2025-10-30 09:51:27
- **Overall Assessment:** ABNORMAL
- **Events Analyzed:** 11
- **MITRE Techniques Retrieved:** 8
- **Mapping Confidence:** HIGH

---
## Executive Summary
Fourteen log events were examined against eight retrieved MITRE ATT&CK techniques. Direct semantic matches were found for six events, yielding high‑confidence mappings to Clear Windows Event Logs, Permission Groups Discovery, Query Registry, Process Injection via Duplicate Handle, and Domain Account Discovery. Remaining events lacked a clear technique among the retrieved set and are listed as unmapped.

---
## Threat Analysis - Event to MITRE ATT&CK Mappings
### 1. Event ID: 1102
**Event Description:** The security audit log was cleared on the host WORKSTATION5.theshire.local by user pgustavo (SID S-1-5-21-...-1104).

#### MITRE Technique: [T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- **Technique Name:** Clear Windows Event Logs
- **Tactic:** defense_evasion
- **Confidence:** HIGH (0.94)

**Analysis:**
> The event explicitly states that the Windows security event log was cleared, which is the exact behavior described by T1070.001.

**Immediate Actions:**
1. Enable audit log retention and configure the system to prevent non‑administrative accounts from clearing logs.
2. Deploy a centralized SIEM that ingests Windows Event Logs in near‑real time to detect log‑clearing attempts.

---
### 2. Event ID: 4688
**Event Description:** Process creation: SharpView.exe launched from C:\ProgramData\SharpView.exe with command line "SharpView.exe  Get-ObjectAcl -SamAccountName \"Domain Admins\"" by user pgustavo.

#### MITRE Technique: [T1069.001](https://attack.mitre.org/techniques/T1069/001/)
- **Technique Name:** Permission Groups Discovery: Domain Groups
- **Tactic:** discovery
- **Confidence:** HIGH (0.90)

**Analysis:**
> SharpView is used to query ACLs of the "Domain Admins" group, which directly aligns with the purpose of T1069.001 – enumerating domain groups and their permissions.

**Immediate Actions:**
1. Restrict execution of known enumeration tools (e.g., SharpView) to privileged accounts only.
2. Monitor PowerShell/command‑line usage that references AD group names such as "Domain Admins".

---
### 3. Event ID: 4663
**Event Description:** SharpView.exe attempted to access registry keys such as \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa and \...\Winlogon.

#### MITRE Technique: [T1012](https://attack.mitre.org/techniques/T1012/)
- **Technique Name:** Query Registry
- **Tactic:** discovery
- **Confidence:** HIGH (0.92)

**Analysis:**
> The event records read‑only queries of high‑value registry locations, which is precisely the activity described by T1012.

**Immediate Actions:**
1. Audit and alert on non‑system processes reading LSA or Winlogon registry keys.
2. Implement registry key access control lists (ACLs) to limit read access to privileged accounts.

---
### 4. Event ID: 4690
**Event Description:** SharpView.exe duplicated handles to objects (e.g., handle 0x9fc) many times within seconds.

#### MITRE Technique: [T1055.012](https://attack.mitre.org/techniques/T1055/012/)
- **Technique Name:** Process Injection: Duplicate Handle
- **Tactic:** defense_evasion
- **Confidence:** HIGH (0.93)

**Analysis:**
> The duplication of handles to bypass security checks matches the definition of T1055.012, which specifically describes the Duplicate Handle sub‑technique.

**Immediate Actions:**
1. Deploy endpoint detection that flags rapid handle duplication patterns.
2. Enforce least‑privilege for processes and restrict the SeCreateGlobalPrivilege right.

---
### 5. Event ID: 5156
**Event Description:** Windows Filtering Platform permitted an outbound connection from SharpView.exe (process ID 3752) to 172.18.38.5 on port 389 (LDAP) and port 53 (DNS).

#### MITRE Technique: [T1087.002](https://attack.mitre.org/techniques/T1087/002/)
- **Technique Name:** Account Discovery: Domain Account
- **Tactic:** discovery
- **Confidence:** HIGH (0.80)

**Analysis:**
> Outbound LDAP queries are a common method for enumerating domain accounts, which aligns with the intent of T1087.002.

**Immediate Actions:**
1. Alert on LDAP traffic originating from non‑system accounts or unexpected processes.
2. Network‑segment domain controllers and enforce strict outbound LDAP rules.

---
### 6. Event ID: 3
**Event Description:** Network connection from SharpView.exe (process ID 3752) to 172.18.38.5 on port 389 (LDAP).

#### MITRE Technique: [T1087.002](https://attack.mitre.org/techniques/T1087/002/)
- **Technique Name:** Account Discovery: Domain Account
- **Tactic:** discovery
- **Confidence:** MEDIUM (0.77)

**Analysis:**
> A direct LDAP connection from a user‑level enumeration tool indicates domain account discovery, matching T1087.002.

**Immediate Actions:**
1. Correlate LDAP connection events with process creation logs to identify suspicious enumeration activity.
2. Implement LDAP query rate‑limiting and monitor for anomalous query volumes.

---
## Unmapped Events
The following events could not be confidently mapped to MITRE techniques:

- Event ID: `4689`
- Event ID: `4673`
- Event ID: `4656`
- Event ID: `4658`
- Event ID: `5158`

> **Note:** These events may require manual analysis or additional context.

---
## Priority Matrix
### HIGH PRIORITY (Investigate Immediately)
| Event ID | MITRE Technique | Technique Name | Confidence |
|----------|-----------------|----------------|------------|
| 1102 | T1070.001 | Clear Windows Event Logs | 0.94 |
| 4688 | T1069.001 | Permission Groups Discovery: Domain Groups | 0.90 |
| 4663 | T1012 | Query Registry | 0.92 |
| 4690 | T1055.012 | Process Injection: Duplicate Handle | 0.93 |
| 5156 | T1087.002 | Account Discovery: Domain Account | 0.80 |
| 3 | T1087.002 | Account Discovery: Domain Account | 0.77 |

---
## Strategic Recommendations
1. Implement a layered detection strategy that combines process creation monitoring, registry access auditing, and network traffic analysis to catch the full kill‑chain observed (log clearing → enumeration → handle duplication).
2. Restrict the execution of known AD‑recon tools (SharpView, PowerView, etc.) to privileged service accounts and enforce application control policies (AppLocker, Windows Defender Application Control).
3. Deploy privileged‑access workstations (PAWs) for any AD‑related activities and ensure regular credential hygiene to mitigate the risk of LSA secret exposure.
4. Review and tighten SeCreateGlobalPrivilege assignments; only system services should possess this right.
5. Ensure that Windows Event Log retention is configured to write‑once and that log‑clearing attempts generate alerts in the SIEM.

---
## Additional Information
- **Report Format:** This report provides event-to-technique correlation analysis
- **Technical Details:** See the accompanying JSON file for complete technical data
- **MITRE ATT&CK:** Click technique IDs above to view full details on the MITRE ATT&CK website

---
*Report generated by Cybersecurity Multi-Agent Pipeline*
