from datetime import datetime
from src.utils.types import MitreAgentInput, SeverityLevel, AnalysisType


def create_sample_log_input() -> MitreAgentInput:
    """Create a sample input for testing."""
    return MitreAgentInput(
        detected_anomalies=[
            {
                "id": "anom_001",
                "description": "Unusual process execution: powershell.exe spawning from winword.exe",
                "timestamp": "2024-01-15T14:30:00Z",
                "confidence": 0.85
            },
            {
                "id": "anom_002",
                "description": "Suspicious network connection to unknown external IP",
                "timestamp": "2024-01-15T14:35:00Z",
                "confidence": 0.72
            }
        ],
        severity=SeverityLevel.HIGH,
        confidence=0.78,
        analysis_type=AnalysisType.INCIDENT_RESPONSE,
        time_window={
            "start": "2024-01-15T14:00:00Z",
            "end": "2024-01-15T15:00:00Z"
        },
        affected_systems=["workstation-001", "dc-primary"],
        indicators={
            "ips": ["192.168.1.100", "10.0.0.5"],
            "domains": ["suspicious-domain.com"],
            "file_hashes": ["a1b2c3d4e5f6"]
        },
        event_types=["process_creation", "network_connection", "file_modification"],
        log_sources=["windows_security", "sysmon", "firewall"],
        user_accounts=["user123", "admin456"],
        processes=["powershell.exe", "cmd.exe", "rundll32.exe"],
        network_activity={
            "external_connections": 5,
            "unusual_ports": [4444, 8080],
            "data_transfer_gb": 2.5
        },
        file_operations={
            "created_files": 3,
            "modified_files": 7,
            "deleted_files": 1
        },
        analysis_id="LOG_ANALYSIS_20240115_001",
        timestamp=datetime.now().isoformat(),
        raw_summary="Detected potential document-based malware execution with C2 communication"
    )

def create_elaborate_mockup_incident() -> MitreAgentInput:
    """Create elaborate incident based on the Starfleet attack scenario (based on IT Security Assignment 2)."""
    return MitreAgentInput(
        detected_anomalies=[
            {
                "id": "anom_001",
                "description": "Suspicious email attachment execution detected on UserLan-PC8",
                "timestamp": "2024-09-09T13:23:14Z",
                "confidence": 0.92
            },
            {
                "id": "anom_002",
                "description": "Abnormal authentication patterns - multiple failed login attempts on Domain Controller",
                "timestamp": "2024-09-10T11:26:01Z",
                "confidence": 0.88
            },
            {
                "id": "anom_003",
                "description": "Unusual PowerShell activity with encoded commands and security bypass",
                "timestamp": "2024-09-10T12:01:00Z",
                "confidence": 0.94
            },
            {
                "id": "anom_004",
                "description": "Suspicious executable (agent.exe) deployed across multiple workstations",
                "timestamp": "2024-09-10T14:35:33Z",
                "confidence": 0.96
            },
            {
                "id": "anom_005",
                "description": "Large volume of sensitive file access by compromised accounts",
                "timestamp": "2024-09-12T11:24:28Z",
                "confidence": 0.89
            }
        ],
        severity=SeverityLevel.CRITICAL,
        confidence=0.91,
        analysis_type=AnalysisType.INCIDENT_RESPONSE,
        time_window={
            "start": "2024-09-09T08:45:00Z",
            "end": "2024-09-12T12:00:00Z"
        },
        affected_systems=[
            "UserLan-PC8",
            "Remote-Access-Server",
            "Domain-Controller",
            "Employee-Workstations"
        ],
        indicators={
            "ips": [
                "171.25.193.25",
                "80.67.167.81",
                "183.81.169.238"
            ],
            "domains": [
                "client.fakeemail.com"
            ],
            "file_hashes": [
                "d806e3e0c84b0b7208fb4ba9df5cd7b8851abce5c0bbb3ee330560aaa139f243",
                "0160375e19e606d06f672be6e43f70fa70093d2a30031affd2929a5c446d07c1"
            ]
        },
        event_types=[
            "email_delivery",
            "file_execution",
            "authentication_failure",
            "authentication_success",
            "process_creation",
            "network_connection",
            "file_access",
            "data_transfer"
        ],
        log_sources=[
            "exchange_logs",
            "windows_security_logs",
            "sysmon_logs",
            "domain_controller_logs",
            "firewall_logs",
            "endpoint_detection_logs"
        ],
        user_accounts=[
            "chris.pike",
            "klingon",
            "admin"
        ],
        processes=[
            "winword.exe",
            "powershell.exe",
            "agent.exe",
            "rundll32.exe"
        ],
        network_activity={
            "external_connections": 23,
            "unusual_ports": [4444, 8080, 443],
            "data_transfer_gb": 15.7
        },
        file_operations={
            "created_files": 12,
            "modified_files": 8,
            "deleted_files": 3
        },
        analysis_id="INCIDENT_STARFLEET_20240909_001",
        timestamp=datetime.now().isoformat(),
        raw_summary="""SECURITY INCIDENT ANALYSIS REPORT

        INCIDENT OVERVIEW:
        Multi-stage cyber attack against organizational infrastructure spanning 72 hours (Sep 9-12, 2024).
        
        ATTACK PROGRESSION:
        1. Email-based compromise initiated through malicious attachment from external domain client.fakeemail.com
        2. Initial system compromise on UserLan-PC8 via document-based malware execution  
        3. Credential harvesting and lateral movement to Remote Access infrastructure
        4. Brute force authentication attack targeting Domain Controller with 15 failed attempts
        5. Administrative account compromise enabling domain-wide access
        6. Malicious payload deployment (agent.exe) across employee workstations
        7. Security control bypass using PowerShell with encoded commands and monitoring evasion
        8. Extensive data access and exfiltration activity detected across sensitive file repositories
        
        TECHNICAL INDICATORS:
        - Suspicious outbound communication to multiple external IP addresses
        - Unusual port usage patterns (4444, 8080) indicating potential backdoor channels  
        - Large data transfer volumes (15.7GB) to external destinations
        - PowerShell execution with policy bypass and real-time protection disabling
        - File system modifications across multiple hosts
        
        IMPACT ASSESSMENT:
        - Domain Controller: Full administrative compromise
        - Multiple workstations: Malware deployment and potential data access
        - User accounts: Credential theft affecting chris.pike, klingon, and admin accounts
        - Data assets: Unauthorized access to sensitive organizational information
        - Network security: Potential persistent access established
        
        CLASSIFICATION: Advanced Persistent Threat (APT) characteristics with multi-vector attack approach"""
    )