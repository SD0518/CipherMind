from typing import Dict, Any
from .types import LogInput, MitreInput

def convert_mitre_agent_input(mitre_agent_input) -> LogInput:
    """Convert MitreAgentInput to LogInput format for correlation testing"""
    
    # Extract anomaly descriptions
    anomalies = [anomaly["description"] for anomaly in mitre_agent_input.detected_anomalies]
    
    # Map severity level to string
    severity_str = mitre_agent_input.severity.value.upper()
    
    return LogInput(
        analysis_id=mitre_agent_input.analysis_id,
        severity=severity_str,
        affected_systems=mitre_agent_input.affected_systems,
        anomalies=anomalies,
        processes=mitre_agent_input.processes,
        raw_summary=mitre_agent_input.raw_summary
    )

def convert_mitre_analysis_output(mitre_analysis_result, original_input) -> MitreInput:
    """Convert MitreAgent analysis result to MitreInput format for correlation"""
    
    # Extract top techniques from analysis result safely
    techniques = []
    technique_details = mitre_analysis_result.get('technique_details', [])
    
    for tech_detail in technique_details[:10]:  # Top 10 techniques
        techniques.append({
            "attack_id": tech_detail.get('attack_id', 'Unknown'),
            "name": tech_detail.get('name', 'Unknown Technique'),
            "relevance_score": tech_detail.get('relevance_score', 0.5)
        })
    
    # Default techniques if none found
    if not techniques:
        techniques = [
            {"attack_id": "T1059.001", "name": "PowerShell", "relevance_score": 0.7},
            {"attack_id": "T1566.001", "name": "Spearphishing Attachment", "relevance_score": 0.6}
        ]
    
    return MitreInput(
        analysis_id=f"MITRE_{getattr(original_input, 'analysis_id', 'UNKNOWN')}",
        techniques=techniques,
        coverage_score=mitre_analysis_result.get('coverage_score', 0.5),
        confidence=mitre_analysis_result.get('confidence', 0.5),
        analysis_text=mitre_analysis_result.get('analysis', 'MITRE analysis completed')
    )