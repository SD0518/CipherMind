from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ConfidenceLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

@dataclass
class LogInput:
    analysis_id: str
    severity: str
    affected_systems: List[str]
    anomalies: List[str]
    processes: List[str]
    raw_summary: str

@dataclass
class MitreInput:
    analysis_id: str
    techniques: List[Dict[str, Any]]
    coverage_score: float
    confidence: float
    analysis_text: str

@dataclass
class MatchedTechnique:
    technique_id: str
    match_confidence: float
    evidence: str
    validation_result: Optional[Dict[str, Any]] = None

@dataclass
class CorrelationOutput:
    correlation_id: str
    correlation_score: float
    threat_level: ThreatLevel
    confidence: ConfidenceLevel
    matched_techniques: List[MatchedTechnique]
    reasoning: str = ""
    timestamp: str = ""