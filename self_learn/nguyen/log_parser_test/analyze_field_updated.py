import json
import json
from collections import defaultdict, Counter
from datetime import datetime

def analyze_log_fields(json_file_path, output_file_path):
    """
    Analyze Windows Event Log fields and generate simple field documentation
    showing frequency, data type, description and sample values.
    """
    
    # Field definitions with descriptions
    field_definitions = {
        # Temporal Fields
        "EventTime": "Timestamp when the event occurred on the source system",
        "EventReceivedTime": "Timestamp when the event was received by the log collection system",
        "@timestamp": "ISO formatted timestamp for event indexing and searching",
        "UtcTime": "UTC timestamp of the event",
        
        # System Identification Fields
        "Hostname": "Name of the computer/system where the event occurred",
        "host": "Log collection host or forwarding system identifier",
        "ComputerName": "Computer name where the event was generated",
        
        # Event Classification Fields
        "EventID": "Unique identifier for the specific type of Windows event",
        "SourceName": "Windows component or service that generated the event",
        "Channel": "Windows Event Log channel (Security, System, Application, etc.)",
        "Category": "Event category providing context about the type of activity",
        "Task": "Task category identifier for the Windows event",
        "Opcode": "Operation code indicating the specific operation performed",
        "OpcodeValue": "Numeric opcode value for programmatic processing",
        "Keywords": "Bitmask indicating event properties and categories",
        "Version": "Event schema version number",
        "@version": "Log processing pipeline version",
        
        # Process and Application Fields
        "ProcessId": "Unique process identifier for the application involved in the event",
        "ExecutionProcessID": "Process ID of the system process handling the event",
        "ThreadID": "Thread identifier within the process that generated the event",
        "Application": "Full path and filename of the application involved in the event",
        "Image": "Full path to the executable image",
        "ProcessGuid": "Globally unique process identifier",
        "ParentProcessId": "Process ID of the parent process",
        "ParentProcessGuid": "Globally unique identifier of the parent process",
        "ParentImage": "Full path to the parent process executable",
        "CommandLine": "Command line used to start the process",
        "ParentCommandLine": "Command line of the parent process",
        "User": "User account associated with the process",
        "LogonGuid": "Logon session identifier",
        "LogonId": "Logon session ID",
        "TerminalSessionId": "Terminal session identifier",
        "IntegrityLevel": "Process integrity level",
        "CurrentDirectory": "Current working directory of the process",
        "NewProcessId": "Process ID of newly created process",
        "NewProcessName": "Path to newly created process",
        "ParentProcessName": "Path to parent process",
        "TokenElevationType": "Token elevation type",
        "MandatoryLabel": "Mandatory integrity label",
        
        # Network Activity Fields
        "SourceAddress": "Source IP address for network connections",
        "DestAddress": "Destination IP address for network connections",
        "SourcePort": "Source port number for network connections",
        "DestPort": "Destination port number for network connections",
        "port": "Port number associated with the network activity",
        "Protocol": "Network protocol number (e.g., 6=TCP, 17=UDP)",
        "Direction": "Network traffic direction (inbound/outbound)",
        "DestinationHostname": "Hostname of the destination",
        "DestinationIp": "Destination IP address",
        "DestinationPort": "Destination port number",
        "SourceIp": "Source IP address",
        "SourceHostname": "Hostname of the source",
        "Initiated": "Whether connection was initiated locally",
        "PipeName": "Named pipe name for inter-process communication",
        "IpAddress": "IP address field",
        "IpPort": "IP port field",
        
        # Registry Fields
        "TargetObject": "Registry key or value that was accessed",
        "Details": "Details of registry operation",
        "PreviousCreationUtcTime": "Previous creation time of registry key",
        
        # File System Fields
        "TargetFilename": "Target filename for file operations",
        "Device": "Device name",
        "CreationUtcTime": "File creation time",
        
        # Security Context Fields
        "RemoteUserID": "Security identifier of remote user in network connections",
        "RemoteMachineID": "Security identifier of remote machine in network connections",
        "SubjectUserName": "User name of the subject",
        "SubjectDomainName": "Domain name of the subject",
        "SubjectLogonId": "Logon ID of the subject",
        "TargetUserName": "Target user name",
        "TargetDomainName": "Target domain name",
        "LogonType": "Type of logon",
        "AuthenticationPackageName": "Authentication package used",
        "LogonProcessName": "Logon process name",
        "WorkstationName": "Workstation name",
        "ImpersonationLevel": "Impersonation level",
        "VirtualAccount": "Virtual account indicator",
        "ElevatedToken": "Elevated token indicator",
        "RestrictedAdminMode": "Restricted admin mode indicator",
        "TargetOutboundUserName": "Target outbound user name",
        "TargetOutboundDomainName": "Target outbound domain name",
        "TargetLinkedLogonId": "Target linked logon ID",
        "LmPackageName": "LM package name",
        "KeyLength": "Key length",
        "TransmittedServices": "Transmitted services",
        "GroupMembership": "Group membership information",
        
        # Event Severity and Priority Fields
        "Severity": "Event severity level (INFO, WARNING, ERROR, CRITICAL)",
        "SeverityValue": "Numeric severity level for programmatic processing",
        "EventType": "Type of audit event (AUDIT_SUCCESS, AUDIT_FAILURE, etc.)",
        "Level": "Event level",
        
        # Technical Metadata Fields
        "ProviderGuid": "Unique identifier for the event provider",
        "RecordNumber": "Sequential record number from the source log",
        
        # Log Processing Fields
        "SourceModuleType": "Type of log collection module used",
        "SourceModuleName": "Name of the log collection module",
        "tags": "Array of tags applied to the event for classification",
        
        # Windows Filtering Platform Fields
        "FilterRTID": "Windows Filtering Platform filter runtime ID",
        "LayerRTID": "Windows Filtering Platform layer runtime ID",
        "LayerName": "Name of the Windows Filtering Platform layer",
        
        # Message and Description Fields
        "Message": "Human-readable description of the event with detailed information",
        
        # PowerShell Fields
        "ScriptBlockId": "PowerShell script block identifier",
        "ScriptBlockText": "PowerShell script block content",
        "MessageNumber": "Message number",
        "MessageTotal": "Total messages",
        
        # WMI Fields
        "QueryName": "WMI query name",
        "QueryResults": "WMI query results",
        "QueryStatus": "WMI query status",
        
        # File/Archive Fields
        "Archived": "Archive status",
        "IsExecutable": "Executable file indicator",
        "Status": "Operation status",
        
        # Event Counting Fields
        "EventIdx": "Event index",
        "EventCountTotal": "Total event count",
        
        # Security Descriptor Fields
        "NewSd": "New security descriptor",
        "OldSd": "Old security descriptor",
        
        # Service Fields
        "Service": "Service name",
        
        # Access Control Fields
        "AccessMask": "Access mask for object access",
        "GrantedAccess": "Granted access permissions",
        "ObjectName": "Name of accessed object",
        "ObjectType": "Type of accessed object",
        
        # Privilege Fields
        "PrivilegeList": "List of privileges",
        "EnabledPrivilegeList": "List of enabled privileges",
        "DisabledPrivilegeList": "List of disabled privileges",
        
        # Parameter Fields
        "param1": "Parameter 1",
        "param2": "Parameter 2"
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
                                            # Clean up sample values
                                            str_value = str(value).strip()
                                            
                                            # Skip very long values (likely structured text)
                                            if len(str_value) > 200:
                                                str_value = str_value[:200] + "..."
                                            
                                            # Replace newlines and multiple spaces with single space
                                            str_value = ' '.join(str_value.split())
                                            
                                            # Skip if this value is already in samples (avoid duplicates)
                                            if str_value not in sample_values[field_name]:
                                                sample_values[field_name].append(str_value)
                                        elif value is None:
                                            if "null" not in sample_values[field_name]:
                                                sample_values[field_name].append("null")
                                        elif isinstance(value, list):
                                            list_desc = f"[array with {len(value)} items]"
                                            if list_desc not in sample_values[field_name]:
                                                sample_values[field_name].append(list_desc)
                                        elif isinstance(value, dict):
                                            dict_desc = f"{{object with {len(value)} fields}}"
                                            if dict_desc not in sample_values[field_name]:
                                                sample_values[field_name].append(dict_desc)
                                    
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
    
    except FileNotFoundError:
        print(f"Error: File {json_file_path} not found")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return
    
    # Generate field documentation
    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        output_file.write("="*100 + "\n")
        output_file.write("WINDOWS EVENT LOG FIELD ANALYSIS\n")
        output_file.write("="*100 + "\n")
        output_file.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        output_file.write(f"Dataset: {json_file_path}\n")
        output_file.write(f"Total Events Processed: {line_num:,}\n")
        output_file.write(f"Unique Fields Discovered: {len(all_fields)}\n")
        output_file.write("="*100 + "\n\n")
        
        # All Fields Section - Sorted by Frequency
        output_file.write("FIELD INVENTORY (Sorted by Frequency)\n")
        output_file.write("="*50 + "\n\n")
        
        # Sort fields by frequency (most common first)
        sorted_fields = sorted(field_frequency.items(), key=lambda x: x[1], reverse=True)
        
        for field_number, (field_name, frequency) in enumerate(sorted_fields, 1):
            # Skip fields that typically contain repetitive structured information
            if field_name.lower() in ['message'] and frequency > 100:
                # For Message field, just show a simplified entry
                if field_name.lower() == 'message':
                    output_file.write(f"{field_number}. Field: {field_name}\n")
                    output_file.write(f"   Frequency: {frequency:,} events ({frequency/line_num*100:.1f}%)\n")
                    output_file.write(f"   Data Types: {', '.join(data_types[field_name])}\n")
                    if field_name in field_definitions:
                        output_file.write(f"   Description: {field_definitions[field_name]}\n")
                    else:
                        output_file.write(f"   Description: Human-readable event message containing structured information\n")
                    output_file.write(f"   Sample Values: [Contains structured event descriptions - too verbose to display]\n")
                    output_file.write("\n")
                continue
            
            output_file.write(f"{field_number}. Field: {field_name}\n")
            output_file.write(f"   Frequency: {frequency:,} events ({frequency/line_num*100:.1f}%)\n")
            output_file.write(f"   Data Types: {', '.join(data_types[field_name])}\n")
            
            # Add field statistics for strings
            if field_name in field_statistics:
                stats = field_statistics[field_name]
                if stats["min_length"] != float('inf'):
                    output_file.write(f"   String Length: {stats['min_length']} - {stats['max_length']} characters\n")
            
            # Add description if available
            if field_name in field_definitions:
                output_file.write(f"   Description: {field_definitions[field_name]}\n")
            else:
                # Provide basic description based on field name patterns
                if 'time' in field_name.lower() or 'date' in field_name.lower():
                    output_file.write(f"   Description: Timestamp field - requires analysis for temporal context\n")
                elif 'address' in field_name.lower() or 'ip' in field_name.lower():
                    output_file.write(f"   Description: Network address field - contains IP address information\n")
                elif 'port' in field_name.lower():
                    output_file.write(f"   Description: Network port field - contains port number information\n")
                elif 'process' in field_name.lower() or 'image' in field_name.lower():
                    output_file.write(f"   Description: Process-related field - contains process execution context\n")
                elif 'user' in field_name.lower():
                    output_file.write(f"   Description: User-related field - contains user account information\n")
                elif 'id' in field_name.lower() or 'guid' in field_name.lower():
                    output_file.write(f"   Description: Identifier field - likely used for correlation and tracking\n")
                else:
                    output_file.write(f"   Description: Field discovered in dataset - requires detailed analysis for context\n")
            
            # Add sample values
            if sample_values[field_name]:
                sample_vals = sample_values[field_name][:5]  # Limit to 5 samples
                output_file.write(f"   Sample Values: {', '.join(map(str, sample_vals))}\n")
            
            output_file.write("\n")
        
        output_file.write("="*100 + "\n")
        output_file.write(f"FIELD ANALYSIS SUMMARY\n")
        output_file.write("="*100 + "\n")
        output_file.write(f"Total Fields Analyzed: {len(sorted_fields)}\n")
        output_file.write(f"Events Processed: {line_num:,}\n")
        output_file.write(f"Most Frequent Field: {sorted_fields[0][0]} ({sorted_fields[0][1]:,} occurrences)\n")
        output_file.write(f"Least Frequent Field: {sorted_fields[-1][0]} ({sorted_fields[-1][1]:,} occurrences)\n")
        output_file.write("="*100 + "\n")
        output_file.write("END OF ANALYSIS\n")
        output_file.write("="*100 + "\n")
    
    print(f"\nAnalysis complete! Field documentation saved to: {output_file_path}")
    print(f"Statistics:")
    print(f"   - Total fields discovered: {len(all_fields)}")
    print(f"   - Events processed: {line_num:,}")
    print(f"   - Most frequent field: {sorted_fields[0][0]} ({sorted_fields[0][1]:,} occurrences)")
    print(f"   - Least frequent field: {sorted_fields[-1][0]} ({sorted_fields[-1][1]:,} occurrences)")

# Usage
if __name__ == "__main__":
    # Update these paths according to your file locations
    input_file = "../mordor_dataset/def_evade_log.json"  # Your input JSON file
    output_file = "field_analysis_numbered.txt"  # Output documentation file

    analyze_log_fields(input_file, output_file)
