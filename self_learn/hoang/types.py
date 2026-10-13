from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Any

class SeverityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AnalysisType(Enum):
    ANOMALY_DETECTION = "anomaly_detection"
    THREAT_HUNTING = "threat_hunting"
    INCIDENT_RESPONSE = "incident_response"
    COMPLIANCE_CHECK = "compliance_check"

@dataclass
class MitreAgentInput:
    """Standardised input from log analysis agent to MITRE agent."""

    # Core findings
    detected_anomalies: List[Dict[str, Any]]  # List of anomalous events/patterns
    severity: SeverityLevel
    confidence: float  # 0.0 to 1.0

    # Context
    analysis_type: AnalysisType
    time_window: Dict[str, str]  # {"start": "2024-01-01T00:00:00Z", "end": "2024-01-01T23:59:59Z"}
    affected_systems: List[str]  # Hostnames, IPs, etc.

    # Technical details
    indicators: Dict[str, List[str]]  # {"ips": [...], "domains": [...], "file_hashes": [...]}
    event_types: List[str]  # ["process_creation", "network_connection", "file_modification"]
    log_sources: List[str]  # ["windows_security", "sysmon", "firewall"]

    # Additional context
    user_accounts: List[str]  # Potentially compromised accounts
    processes: List[str]  # Suspicious processes
    network_activity: Dict[str, Any]  # Network patterns, connections
    file_operations: Dict[str, Any]  # File creation/modification/deletion

    # Metadata
    analysis_id: str
    timestamp: str
    raw_summary: str  # Natural language summary from log analysis
