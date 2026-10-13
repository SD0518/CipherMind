import json
import json
from collections import defaultdict, Counter
from datetime import datetime

def analyze_log_fields(json_file_path, output_file_path):
    """
    Analyze Windows Event Log fields and generate comprehensive documentation
    for security analysts and log agents.
    """
    
    # Comprehensive field definitions and their meanings for security analysis
    field_definitions = {
        # Temporal Fields
        "EventTime": {
            "description": "Timestamp when the event occurred on the source system",
            "security_relevance": "Critical for timeline analysis, correlation with other events, and identifying attack sequences",
            "log_agent_use": "Time-based filtering, chronological ordering, temporal pattern detection, attack chain reconstruction"
        },
        "EventReceivedTime": {
            "description": "Timestamp when the event was received by the log collection system",
            "security_relevance": "Helps identify log delivery delays and system clock synchronization issues",
            "log_agent_use": "Log pipeline health monitoring, event freshness validation, correlation accuracy assessment"
        },
        "@timestamp": {
            "description": "ISO formatted timestamp for event indexing and searching",
            "security_relevance": "Standardized time format for consistent temporal analysis across different log sources",
            "log_agent_use": "Primary time field for indexing, search optimization, cross-source correlation"
        },
        
        # System Identification Fields
        "Hostname": {
            "description": "Name of the computer/system where the event occurred",
            "security_relevance": "Identifies affected systems, tracks lateral movement across network, maps attack scope",
            "log_agent_use": "Host-based filtering, compromised endpoint identification, network topology mapping, asset tracking"
        },
        "host": {
            "description": "Log collection host or forwarding system identifier",
            "security_relevance": "Distinguishes between source system and log collector, helps identify log tampering",
            "log_agent_use": "Log source validation, collection infrastructure monitoring, data integrity verification"
        },
        
        # Event Classification Fields
        "EventID": {
            "description": "Unique identifier for the specific type of Windows event (e.g., 5156=network connection)",
            "security_relevance": "Each ID represents specific system activities critical for threat detection and forensics",
            "log_agent_use": "Event categorization, signature matching, automated rule creation, threat pattern recognition"
        },
        "SourceName": {
            "description": "Windows component or service that generated the event",
            "security_relevance": "Identifies which Windows subsystem detected the activity, helps assess event reliability",
            "log_agent_use": "Source-based filtering, reliability scoring, component-specific analysis rules"
        },
        "Channel": {
            "description": "Windows Event Log channel (Security, System, Application, etc.)",
            "security_relevance": "Indicates the log source and helps prioritize events based on security relevance",
            "log_agent_use": "Channel-based routing, priority assignment, log source validation, analysis workflow optimization"
        },
        "Category": {
            "description": "Event category providing context about the type of activity",
            "security_relevance": "Groups related security events for pattern analysis and threat detection",
            "log_agent_use": "Category-based filtering, threat taxonomy mapping, automated alert classification"
        },
        
        # Process and Application Fields
        "ProcessId": {
            "description": "Unique process identifier for the application involved in the event",
            "security_relevance": "Essential for tracking process behavior, parent-child relationships, and attack chains",
            "log_agent_use": "Process correlation across events, behavioral analysis, attack path reconstruction"
        },
        "ExecutionProcessID": {
            "description": "Process ID of the system process handling the event",
            "security_relevance": "Helps identify system-level process involvement and potential privilege escalation",
            "log_agent_use": "System process monitoring, privilege escalation detection, kernel-level activity tracking"
        },
        "ThreadID": {
            "description": "Thread identifier within the process that generated the event",
            "security_relevance": "Provides granular tracking of process activities and multi-threaded attack techniques",
            "log_agent_use": "Thread-level analysis, concurrent activity detection, fine-grained process behavior tracking"
        },
        "Application": {
            "description": "Full path and filename of the application involved in the event",
            "security_relevance": "Critical for identifying malicious executables, legitimate tool abuse, and file-based attacks",
            "log_agent_use": "Application whitelisting/blacklisting, executable reputation checking, threat hunting"
        },
        
        # Network Activity Fields
        "SourceAddress": {
            "description": "Source IP address for network connections",
            "security_relevance": "Identifies connection origins, helps detect lateral movement and external threats",
            "log_agent_use": "IP reputation checking, geolocation analysis, network behavior profiling, threat intelligence correlation"
        },
        "DestAddress": {
            "description": "Destination IP address for network connections",
            "security_relevance": "Identifies connection targets, C2 servers, and data exfiltration destinations",
            "log_agent_use": "Destination analysis, C2 detection, data exfiltration monitoring, threat intelligence matching"
        },
        "SourcePort": {
            "description": "Source port number for network connections",
            "security_relevance": "Helps identify service types and detect port-based attacks or unusual communications",
            "log_agent_use": "Port analysis, service identification, protocol validation, anomaly detection"
        },
        "DestPort": {
            "description": "Destination port number for network connections",
            "security_relevance": "Identifies target services and protocols, helps detect service exploitation",
            "log_agent_use": "Service targeting analysis, protocol identification, port scanning detection"
        },
        "port": {
            "description": "Port number associated with the network activity",
            "security_relevance": "Additional port context for network behavior analysis",
            "log_agent_use": "Supplementary port information for correlation and validation"
        },
        "Protocol": {
            "description": "Network protocol number (e.g., 6=TCP, 17=UDP)",
            "security_relevance": "Identifies communication protocols and helps detect protocol anomalies",
            "log_agent_use": "Protocol analysis, traffic classification, communication pattern detection"
        },
        "Direction": {
            "description": "Network traffic direction (inbound/outbound)",
            "security_relevance": "Critical for identifying data exfiltration, C2 communications, and lateral movement",
            "log_agent_use": "Traffic flow analysis, directional filtering, communication pattern analysis"
        },
        
        # Security Context Fields
        "RemoteUserID": {
            "description": "Security identifier of remote user in network connections",
            "security_relevance": "Tracks user context in network activities, helps identify compromised accounts",
            "log_agent_use": "User activity correlation, account compromise detection, remote access monitoring"
        },
        "RemoteMachineID": {
            "description": "Security identifier of remote machine in network connections",
            "security_relevance": "Identifies remote systems involved in network communications",
            "log_agent_use": "Remote system tracking, lateral movement detection, trust relationship analysis"
        },
        
        # Event Severity and Priority Fields
        "Severity": {
            "description": "Event severity level (INFO, WARNING, ERROR, CRITICAL)",
            "security_relevance": "Helps prioritize events and identify high-impact security incidents",
            "log_agent_use": "Event prioritization, alert severity assignment, escalation workflows"
        },
        "SeverityValue": {
            "description": "Numeric severity level for programmatic processing",
            "security_relevance": "Enables automated severity-based processing and filtering",
            "log_agent_use": "Numeric severity filtering, threshold-based alerting, priority scoring"
        },
        "EventType": {
            "description": "Type of audit event (AUDIT_SUCCESS, AUDIT_FAILURE, etc.)",
            "security_relevance": "Distinguishes between successful and failed activities, critical for breach detection",
            "log_agent_use": "Success/failure analysis, authentication monitoring, access control validation"
        },
        
        # Technical Metadata Fields
        "Task": {
            "description": "Task category identifier for the Windows event",
            "security_relevance": "Groups related Windows activities for pattern analysis",
            "log_agent_use": "Task-based filtering, Windows activity categorization, event correlation"
        },
        "Opcode": {
            "description": "Operation code indicating the specific operation performed",
            "security_relevance": "Provides granular details about the type of operation for forensic analysis",
            "log_agent_use": "Operation-specific analysis, detailed event classification, forensic investigation support"
        },
        "OpcodeValue": {
            "description": "Numeric opcode value for programmatic processing",
            "security_relevance": "Enables automated opcode-based analysis and filtering",
            "log_agent_use": "Numeric opcode filtering, automated classification, pattern matching"
        },
        "Keywords": {
            "description": "Bitmask indicating event properties and categories",
            "security_relevance": "Provides metadata about event characteristics for advanced analysis",
            "log_agent_use": "Keyword-based filtering, event property analysis, advanced correlation"
        },
        "Version": {
            "description": "Event schema version number",
            "security_relevance": "Ensures correct parsing and interpretation of event data",
            "log_agent_use": "Schema validation, version-specific parsing, data integrity verification"
        },
        "@version": {
            "description": "Log processing pipeline version",
            "security_relevance": "Tracks log processing changes that might affect analysis",
            "log_agent_use": "Pipeline version tracking, processing consistency validation"
        },
        
        # Log Processing Fields
        "SourceModuleType": {
            "description": "Type of log collection module used",
            "security_relevance": "Identifies how logs were collected, affects data quality and completeness",
            "log_agent_use": "Collection method validation, data quality assessment, parsing rule selection"
        },
        "SourceModuleName": {
            "description": "Name of the log collection module",
            "security_relevance": "Specific collector identification for troubleshooting and validation",
            "log_agent_use": "Collector-specific processing, data source validation, quality control"
        },
        "RecordNumber": {
            "description": "Sequential record number from the source log",
            "security_relevance": "Helps detect missing events and maintain event sequence integrity",
            "log_agent_use": "Sequence validation, gap detection, log completeness verification"
        },
        
        # Windows Filtering Platform Fields
        "FilterRTID": {
            "description": "Windows Filtering Platform filter runtime ID",
            "security_relevance": "Identifies specific network filtering rules applied to connections",
            "log_agent_use": "Filter-based analysis, network policy enforcement tracking, firewall rule correlation"
        },
        "LayerRTID": {
            "description": "Windows Filtering Platform layer runtime ID",
            "security_relevance": "Identifies the network stack layer where filtering occurred",
            "log_agent_use": "Network layer analysis, protocol stack monitoring, traffic flow understanding"
        },
        "LayerName": {
            "description": "Name of the Windows Filtering Platform layer",
            "security_relevance": "Provides context about where in the network stack the event occurred",
            "log_agent_use": "Layer-specific analysis, network troubleshooting, protocol behavior monitoring"
        },
        
        # Provider and GUID Fields
        "ProviderGuid": {
            "description": "Unique identifier for the event provider",
            "security_relevance": "Identifies the specific Windows component that generated the event",
            "log_agent_use": "Provider-based filtering, component reliability assessment, source validation"
        },
        
        # Message and Description Fields
        "Message": {
            "description": "Human-readable description of the event with detailed information",
            "security_relevance": "Contains rich contextual information for manual analysis and investigation",
            "log_agent_use": "Text analysis, keyword extraction, natural language processing for threat detection"
        },
        
        # Tagging and Classification Fields
        "tags": {
            "description": "Array of tags applied to the event for classification",
            "security_relevance": "Provides metadata for event categorization and filtering",
            "log_agent_use": "Tag-based filtering, event classification, automated labeling workflows"
        }
    }
    
    all_fields = set()
    sample_values = defaultdict(list)
    field_frequency = Counter()
    data_types = defaultdict(set)
    field_statistics = defaultdict(lambda: {"min_length": float('inf'), "max_length": 0, "unique_values": set()})
    
    print(f"Analyzing log file: {json_file_path}")
    
    try:
        with open(json_file_path, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file, 1):
                try:
                    if line.strip():  # Skip empty lines
                        event = json.loads(line)
                        
                        # Extract all fields recursively
                        def extract_fields(obj, prefix=""):
                            if isinstance(obj, dict):
                                for key, value in obj.items():
                                    field_name = f"{prefix}.{key}" if prefix else key
                                    all_fields.add(field_name)
                                    field_frequency[field_name] += 1
                                    
                                    # Track data types
                                    data_types[field_name].add(type(value).__name__)
                                    
                                    # Collect sample values and statistics (limit to prevent memory issues)
                                    if len(sample_values[field_name]) < 5:
                                        if isinstance(value, (str, int, float, bool)):
                                            sample_values[field_name].append(str(value))
                                        elif value is None:
                                            sample_values[field_name].append("null")
                                        elif isinstance(value, list):
                                            sample_values[field_name].append(f"[array with {len(value)} items]")
                                        elif isinstance(value, dict):
                                            sample_values[field_name].append(f"{{object with {len(value)} fields}}")
                                    
                                    # Track field statistics for strings
                                    if isinstance(value, str):
                                        field_stats = field_statistics[field_name]
                                        field_stats["min_length"] = min(field_stats["min_length"], len(value))
                                        field_stats["max_length"] = max(field_stats["max_length"], len(value))
                                        if len(field_stats["unique_values"]) < 10:
                                            field_stats["unique_values"].add(value)
                                    
                                    # Recurse into nested objects
                                    if isinstance(value, dict):
                                        extract_fields(value, field_name)
                                    elif isinstance(value, list) and value and isinstance(value[0], dict):
                                        extract_fields(value[0], field_name)
                            elif isinstance(obj, list):
                                for i, item in enumerate(obj[:3]):  # Only check first 3 items
                                    if isinstance(item, dict):
                                        extract_fields(item, f"{prefix}[{i}]" if prefix else f"[{i}]")
                        
                        extract_fields(event)
                        
                        if line_num % 1000 == 0:
                            print(f"Processed {line_num} events...")
                            
                except json.JSONDecodeError as e:
                    print(f"JSON parsing error on line {line_num}: {e}")
                    continue
        "Hostname": {
            "description": "Name of the computer where the event occurred",
            "security_relevance": "Identifies affected systems, tracks lateral movement across network",
            "log_agent_use": "Host-based filtering, identifying compromised endpoints, network topology mapping"
        },
        "EventID": {
            "description": "Unique identifier for the type of Windows event",
            "security_relevance": "Each ID represents specific system activities (e.g., 4688=process creation, 4624=logon)",
            "log_agent_use": "Event categorization, rule creation, signature matching for known attack patterns"
        },
        "LogName": {
            "description": "Windows Event Log channel name",
            "security_relevance": "Indicates data source (Security, System, Application logs)",
            "log_agent_use": "Log source validation, data quality assurance, routing to appropriate analyzers"
        },
        "SourceName": {
            "description": "Component or service that generated the event",
            "security_relevance": "Identifies which Windows component detected the activity",
            "log_agent_use": "Source reliability assessment, filtering by trusted/untrusted sources"
        },
        "Level": {
            "description": "Event severity level (Information, Warning, Error, Critical)",
            "security_relevance": "Helps prioritize events, errors may indicate attack impact",
            "log_agent_use": "Alert prioritization, severity-based routing, noise reduction"
        },
        
        # Process Information
        "NewProcessName": {
            "description": "Full path of newly created process",
            "security_relevance": "Critical for detecting malicious executables, living-off-the-land attacks",
            "log_agent_use": "Process whitelist/blacklist matching, behavioral analysis, threat hunting"
        },
        "CommandLine": {
            "description": "Complete command line used to start the process",
            "security_relevance": "Reveals attack techniques, encoded commands, suspicious parameters",
            "log_agent_use": "Signature detection, command injection analysis, technique identification"
        },
        "ProcessId": {
            "description": "Unique process identifier",
            "security_relevance": "Tracks process relationships, parent-child chains",
            "log_agent_use": "Process tree reconstruction, correlation across multiple events"
        },
        "ParentProcessName": {
            "description": "Name of the parent process that spawned the new process",
            "security_relevance": "Detects process injection, unusual parent-child relationships",
            "log_agent_use": "Behavioral analysis, detecting living-off-the-land techniques"
        },
        "ParentProcessId": {
            "description": "Process ID of the parent process",
            "security_relevance": "Links processes in attack chains, identifies process hollowing",
            "log_agent_use": "Process genealogy tracking, attack path reconstruction"
        },
        
        # User and Session Information
        "SubjectUserName": {
            "description": "Username of the account that initiated the action",
            "security_relevance": "Identifies potentially compromised accounts, privilege escalation",
            "log_agent_use": "User behavior analysis, account compromise detection, access pattern analysis"
        },
        "SubjectDomainName": {
            "description": "Domain of the user account",
            "security_relevance": "Distinguishes local vs domain accounts, identifies domain compromise",
            "log_agent_use": "Domain-based filtering, privilege level assessment"
        },
        "SubjectLogonId": {
            "description": "Unique session identifier for the user logon",
            "security_relevance": "Tracks actions within specific login sessions",
            "log_agent_use": "Session-based correlation, tracking user activities across time"
        },
        "TargetUserName": {
            "description": "Username of the target account (for account-related events)",
            "security_relevance": "Identifies accounts being targeted or modified",
            "log_agent_use": "Account monitoring, privilege escalation detection"
        },
        "LogonType": {
            "description": "Method of logon (Interactive, Network, Batch, Service, etc.)",
            "security_relevance": "Different logon types indicate different attack vectors",
            "log_agent_use": "Logon pattern analysis, detecting unusual access methods"
        },
        
        # System and Registry Information
        "ObjectName": {
            "description": "Name of the object being accessed or modified",
            "security_relevance": "Critical files, registry keys, or resources being targeted",
            "log_agent_use": "Critical asset monitoring, detecting access to sensitive resources"
        },
        "ObjectType": {
            "description": "Type of object (File, Registry, Process, etc.)",
            "security_relevance": "Categorizes the type of system resource involved",
            "log_agent_use": "Object-type specific analysis rules, categorized threat detection"
        },
        "AccessMask": {
            "description": "Permissions requested or granted",
            "security_relevance": "Unusual permission requests may indicate privilege escalation",
            "log_agent_use": "Permission-based anomaly detection, privilege monitoring"
        },
        
        # Defense Evasion Specific Fields
        "TokenElevationType": {
            "description": "Type of token elevation (None, Default, Full, Limited)",
            "security_relevance": "Indicates UAC bypass attempts or privilege escalation",
            "log_agent_use": "UAC bypass detection, privilege escalation monitoring"
        },
        "MandatoryLabel": {
            "description": "Integrity level of the process or object",
            "security_relevance": "High integrity processes are prime targets for attackers",
            "log_agent_use": "Integrity level monitoring, detecting elevation attempts"
        },
        "ProcessName": {
            "description": "Name of the process involved in the event",
            "security_relevance": "Quick identification of suspicious processes",
            "log_agent_use": "Fast process-based filtering and alerting"
        }
    }
    
    all_fields = set()
    sample_values = defaultdict(list)
    field_frequency = Counter()
    
    print(f"Analyzing log file: {json_file_path}")
    
    try:
        with open(json_file_path, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file, 1):
                try:
                    if line.strip():  # Skip empty lines
                        event = json.loads(line)
                        
                        # Extract all fields recursively
                        def extract_fields(obj, prefix=""):
                            if isinstance(obj, dict):
                                for key, value in obj.items():
                                    field_name = f"{prefix}.{key}" if prefix else key
                                    all_fields.add(field_name)
                                    field_frequency[field_name] += 1
                                    
                                    # Collect sample values (limit to prevent memory issues)
                                    if len(sample_values[field_name]) < 5:
                                        if isinstance(value, (str, int, float, bool)):
                                            sample_values[field_name].append(str(value))
                                        elif value is None:
                                            sample_values[field_name].append("null")
                                    
                                    # Recurse into nested objects
                                    if isinstance(value, dict):
                                        extract_fields(value, field_name)
                                    elif isinstance(value, list) and value and isinstance(value[0], dict):
                                        extract_fields(value[0], field_name)
                        
                        extract_fields(event)
                        
                        if line_num % 1000 == 0:
                            print(f"Processed {line_num} events...")
                            
                except json.JSONDecodeError as e:
                    print(f"JSON parsing error on line {line_num}: {e}")
                    continue
    
    except FileNotFoundError:
        print(f"Error: File {json_file_path} not found")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return
    
    # Generate comprehensive documentation
    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        output_file.write("="*80 + "\n")
        output_file.write("WINDOWS EVENT LOG FIELD ANALYSIS FOR DEFENSE EVASION DETECTION\n")
        output_file.write("="*80 + "\n")
        output_file.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        output_file.write(f"Total Events Processed: {line_num}\n")
        output_file.write(f"Unique Fields Discovered: {len(all_fields)}\n")
        output_file.write("="*80 + "\n\n")
        
        # Critical Fields Section
        output_file.write("CRITICAL FIELDS FOR DEFENSE EVASION DETECTION\n")
        output_file.write("="*50 + "\n\n")
        
        critical_fields = ['EventID', 'CommandLine', 'NewProcessName', 'ParentProcessName', 
                          'SubjectUserName', 'TokenElevationType', 'ProcessName']
        
        for field in critical_fields:
            if field in all_fields:
                output_file.write(f"🔥 {field}\n")
                output_file.write(f"   Frequency: {field_frequency[field]} events\n")
                if field in field_definitions:
                    output_file.write(f"   Description: {field_definitions[field]['description']}\n")
                    output_file.write(f"   Security Relevance: {field_definitions[field]['security_relevance']}\n")
                    output_file.write(f"   Log Agent Use: {field_definitions[field]['log_agent_use']}\n")
                if sample_values[field]:
                    output_file.write(f"   Sample Values: {', '.join(sample_values[field][:3])}\n")
                output_file.write("\n")
        
        # All Fields Section
        output_file.write("\n" + "="*50 + "\n")
        output_file.write("ALL DISCOVERED FIELDS (Sorted by Frequency)\n")
        output_file.write("="*50 + "\n\n")
        
        # Sort fields by frequency (most common first)
        sorted_fields = sorted(field_frequency.items(), key=lambda x: x[1], reverse=True)
        
        for field_name, frequency in sorted_fields:
            output_file.write(f"Field: {field_name}\n")
            output_file.write(f"  Frequency: {frequency} events ({frequency/line_num*100:.1f}%)\n")
            
            # Add definition if available
            if field_name in field_definitions:
                output_file.write(f"  Description: {field_definitions[field_name]['description']}\n")
                output_file.write(f"  Security Relevance: {field_definitions[field_name]['security_relevance']}\n")
                output_file.write(f"  Log Agent Use: {field_definitions[field_name]['log_agent_use']}\n")
            else:
                output_file.write(f"  Description: Field discovered in dataset (definition needed)\n")
                output_file.write(f"  Security Relevance: Requires analysis for security context\n")
                output_file.write(f"  Log Agent Use: Potential for custom rules and correlation\n")
            
            # Add sample values
            if sample_values[field_name]:
                output_file.write(f"  Sample Values: {', '.join(sample_values[field_name])}\n")
            
            output_file.write("\n")
        
        # Defense Evasion Techniques Section
        output_file.write("="*50 + "\n")
        output_file.write("DEFENSE EVASION TECHNIQUES DETECTABLE WITH THESE FIELDS\n")
        output_file.write("="*50 + "\n\n")
        
        techniques = [
            ("T1055 - Process Injection", "ProcessId, ParentProcessId, ProcessName, CommandLine"),
            ("T1070 - Indicator Removal", "ObjectName, ObjectType, ProcessName, CommandLine"),
            ("T1112 - Modify Registry", "ObjectName (registry keys), AccessMask, SubjectUserName"),
            ("T1036 - Masquerading", "ProcessName, NewProcessName, CommandLine"),
            ("T1548 - Abuse Elevation Control", "TokenElevationType, MandatoryLabel, SubjectUserName"),
            ("T1134 - Access Token Manipulation", "TokenElevationType, SubjectLogonId, ProcessId"),
            ("T1027 - Obfuscated Files/Info", "CommandLine, NewProcessName, ProcessName"),
            ("T1222 - File/Directory Permissions", "ObjectName, AccessMask, SubjectUserName")
        ]
        
        for technique, relevant_fields in techniques:
            output_file.write(f"🎯 {technique}\n")
            output_file.write(f"   Key Fields: {relevant_fields}\n")
            output_file.write(f"   Detection Strategy: Monitor these fields for unusual patterns\n\n")
        
        # Log Agent Configuration Recommendations
        output_file.write("="*50 + "\n")
        output_file.write("LOG AGENT CONFIGURATION RECOMMENDATIONS\n")
        output_file.write("="*50 + "\n\n")
        
        recommendations = [
            "1. HIGH PRIORITY MONITORING:",
            "   - EventID: Focus on 4688 (process creation), 4624/4625 (logon events)",
            "   - CommandLine: Enable command line logging in Windows",
            "   - ProcessName + ParentProcessName: Track process relationships",
            "",
            "2. REAL-TIME ALERTING:",
            "   - Unusual parent-child process relationships",
            "   - High-privilege token elevation events",
            "   - Suspicious command line patterns",
            "",
            "3. CORRELATION RULES:",
            "   - Group events by SubjectLogonId for session analysis",
            "   - Link ProcessId across multiple events",
            "   - Time-based correlation using EventTime",
            "",
            "4. PERFORMANCE OPTIMIZATION:",
            "   - Index frequently queried fields (EventID, Hostname, ProcessName)",
            "   - Set retention policies based on field frequency",
            "   - Use field frequency data to optimize storage",
        ]
        
        for rec in recommendations:
            output_file.write(f"{rec}\n")
    
    print(f"\nAnalysis complete! Documentation saved to: {output_file_path}")
    print(f"Total fields discovered: {len(all_fields)}")
    print(f"Events processed: {line_num}")

# Usage
if __name__ == "__main__":
    # Update these paths according to your file locations
    input_file = "mordor_dataset/defense_evasion_log_cut.json"  # Your input JSON file
    output_file = "windows_event_fields_analysis.txt"  # Output documentation file
    
    analyze_log_fields(input_file, output_file)