# LLM Log Analysis Agent Specification

## Overview
This document specifies the requirements and data structures needed for an LLM-powered Windows security log analysis agent that can detect anomalous behavior and map findings to MITRE ATT&CK techniques.

## Log Data Structure Analysis

### Event Sources Distribution
Based on analysis of defense evasion logs, the agent should handle:

- **Microsoft-Windows-Sysmon** (73.7% of events)
  - Process monitoring, network connections, file/registry operations
  - Critical for behavioral analysis and attack chain reconstruction

- **Microsoft-Windows-Security-Auditing** (21.4% of events)  
  - Authentication, privilege escalation, object access
  - Essential for security policy violations and access anomalies

- **PowerShell Events** (4.8% of events)
  - Script execution, command-line activities
  - Key indicator of living-off-the-land attacks

- **WMI Activity** (0.1% of events)
  - System management operations
  - Often abused for persistence and lateral movement

### Critical Event Types for Analysis

#### High-Priority Events (Most Frequent)
1. **Sysmon Event 12** (Registry Object Added/Deleted) - 28.5% of logs
2. **Sysmon Event 7** (Image Loaded) - 22.4% of logs  
3. **Sysmon Event 10** (Process Access) - 11.1% of logs
4. **Security Event 5156** (Network Connection Allowed) - 9.0% of logs
5. **Sysmon Event 13** (Registry Value Set) - 8.9% of logs

#### Security-Critical Events (Lower Frequency, High Importance)
- **Sysmon Event 1** (Process Creation) - Process execution chains
- **Sysmon Event 3** (Network Connection) - C2 communications
- **Security Event 4688** (Process Creation) - Privileged process spawning
- **Security Event 4624/4634** (Logon/Logoff) - Authentication anomalies
- **PowerShell 4103/4104** (Script Execution) - Malicious script detection

## Field Categories for Analysis

### Core Event Fields
- `EventID`, `SourceName`, `Channel`, `Message`, `Category`, `Task`
- Essential for event classification and basic understanding

### Temporal Analysis Fields  
- `@timestamp`, `EventReceivedTime`, `EventTime`, `UtcTime`
- Critical for timeline reconstruction and correlation

### Process Behavior Fields
- `Image`, `ProcessId`, `ProcessGuid`, `ParentProcessId`, `ParentImage`
- `CommandLine`, `ParentCommandLine`, `ExecutionProcessID`
- Key for attack chain analysis and process genealogy

### Network Activity Fields
- `SourceAddress`, `DestAddress`, `SourcePort`, `DestPort`
- `Protocol`, `Direction`, `DestinationHostname`
- Essential for C2 detection and lateral movement

### Security Context Fields
- `User`, `UserID`, `LogonId`, `SubjectUserName`, `TargetUserName`
- `AccessMask`, `GrantedAccess`, `PrivilegeList`
- Critical for privilege escalation and unauthorized access detection

## Agent Processing Strategy

### Phase 1: Event Normalization
```
Input: Raw heterogeneous log events
Output: Standardized event objects with consistent field mapping
```

**Key Normalizations:**
- Timestamp standardization across different log sources
- Process ID/GUID correlation between Sysmon and Security events
- User identity mapping (UserID, SubjectUserName variations)
- Network address format consistency

### Phase 2: Contextual Enrichment
```  
Input: Normalized events
Output: Events with relationship metadata and behavioral context
```

**Enrichment Types:**
- **Process Lineage**: Parent-child relationships, execution chains
- **Temporal Correlation**: Events within time windows (±5 minutes)
- **Host Correlation**: Activities grouped by hostname/machine
- **User Session Tracking**: Activities grouped by logon sessions

### Phase 3: Anomaly Detection
```
Input: Enriched event sequences  
Output: Risk-scored event clusters with anomaly indicators
```

**Detection Categories:**
- **Process Anomalies**: Unusual parent-child relationships, suspicious locations
- **Network Anomalies**: Connections to unusual destinations, protocol misuse
- **Persistence Anomalies**: Registry/file modifications in security-critical locations
- **Privilege Anomalies**: Unexpected elevation or access patterns

### Phase 4: Attack Pattern Recognition
```
Input: Anomalous event clusters
Output: Structured threat assessment with MITRE technique mapping
```

## Suspicious Indicators Framework

### Process-Based Indicators
- **Suspicious Parent Processes**: Office apps spawning shells/interpreters
- **Unusual Process Locations**: Execution from temp directories, user folders
- **Process Masquerading**: Legitimate names in wrong locations
- **Injection Indicators**: Process access with specific granted access patterns

### Network-Based Indicators  
- **C2 Communications**: Outbound connections to uncommon ports/protocols
- **Internal Reconnaissance**: Port scanning, SMB enumeration patterns
- **Data Exfiltration**: Large data transfers to external addresses
- **Tunneling**: DNS/HTTPS traffic with unusual characteristics

### Registry/File-Based Indicators
- **Persistence Mechanisms**: Run keys, services, scheduled tasks
- **Defense Evasion**: Security tool disabling, logging modifications  
- **Credential Access**: SAM/SYSTEM file access, credential dumping locations
- **Discovery Activities**: System/network enumeration artifacts

### Temporal-Based Indicators
- **Rapid Event Sequences**: Multiple related events in short timeframes
- **Off-Hours Activity**: Unusual activity during non-business hours
- **Synchronized Actions**: Coordinated activities across multiple systems

## Output Specification for MITRE Technique Retrieval

### Required Output Structure
```json
{
  "analysis_id": "unique_identifier",
  "timestamp": "2024-XX-XX HH:MM:SS",
  "risk_assessment": {
    "overall_risk": "HIGH|MEDIUM|LOW", 
    "confidence_score": 0.85,
    "evidence_strength": "STRONG|MODERATE|WEAK"
  },
  "threat_classification": {
    "attack_category": "Defense Evasion|Credential Access|Discovery|...",
    "suspected_techniques": [
      {
        "technique_name": "PowerShell Execution",
        "mitre_id": "T1059.001", 
        "confidence": 0.9,
        "evidence_events": ["event_id_1", "event_id_2"]
      }
    ]
  },
  "key_findings": {
    "anomalous_processes": ["process_name_1", "process_name_2"],
    "suspicious_network": ["ip_address_1", "domain_name_1"], 
    "registry_modifications": ["registry_key_1"],
    "affected_systems": ["hostname_1", "hostname_2"]
  },
  "attack_timeline": [
    {
      "timestamp": "2024-XX-XX HH:MM:SS",
      "event_type": "Process Creation",
      "description": "Suspicious PowerShell execution",
      "risk_contribution": 0.3
    }
  ],
  "mitre_query_keywords": [
    "powershell", "registry modification", "process injection", 
    "defense evasion", "credential access"
  ],
  "recommended_actions": [
    "Investigate PowerShell command history",
    "Check for additional registry modifications",
    "Validate user account legitimacy"
  ]
}
```

### MITRE Technique Mapping Strategy

**Primary Mapping Approach:**
1. **Event Pattern → Technique**: Map specific event sequences to known techniques
2. **Behavioral Indicators → Tactic**: Group related anomalies under MITRE tactics
3. **Tool/Process → Technique**: Known malicious tools to their common techniques
4. **Context Enrichment**: Use additional metadata to refine technique selection

**Query Generation for Vector Database:**
- **Primary Keywords**: Direct technique names and IDs
- **Secondary Keywords**: Related tools, processes, and methods  
- **Contextual Terms**: Attack phase, target system type, persistence methods
- **Semantic Expansion**: Synonyms and related concepts for broader matching

## Implementation Considerations

### Performance Optimization
- **Batch Processing**: Analyze log chunks rather than individual events
- **Priority Filtering**: Focus analysis on high-value event types first
- **Caching**: Store common pattern recognition results
- **Streaming**: Real-time analysis for live monitoring scenarios

### Accuracy Improvements  
- **False Positive Reduction**: Maintain whitelist of known-good patterns
- **Context Awareness**: Consider business processes and normal operations
- **Feedback Loop**: Learn from analyst corrections and validations
- **Confidence Calibration**: Adjust scoring based on evidence quality

### Scalability Requirements
- **Horizontal Scaling**: Process multiple log sources in parallel
- **Memory Management**: Efficient handling of large log volumes
- **State Management**: Track analysis context across log segments
- **Integration**: Seamless handoff to MITRE technique retrieval system

## Testing and Validation Framework

### Test Data Categories
- **Known Attack Patterns**: Validated malicious activity logs
- **Benign Baselines**: Normal operational activity samples  
- **Edge Cases**: Unusual but legitimate system behaviors
- **Mixed Scenarios**: Combination of normal and malicious activities

### Evaluation Metrics
- **Detection Rate**: Percentage of actual threats identified
- **False Positive Rate**: Benign activities flagged as malicious
- **Attribution Accuracy**: Correctness of MITRE technique mapping
- **Processing Speed**: Events analyzed per second/minute

This specification provides the foundation for building an effective LLM-powered log analysis agent that can accurately detect threats and provide actionable intelligence for further investigation.
