"""
LLM-based Mordor Log Analysis Agent using LangGraph
- Uses LangGraph for workflow orchestration
- Employs prompt engineering for intelligent threat detection
- Generates comprehensive security reports with AI insights
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, TypedDict
from dataclasses import dataclass, asdict
from datetime import datetime
import asyncio
import sys
# Ensure project root is in PYTHONPATH for utils import
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
from utils.types import MitreAgentInput, SeverityLevel, AnalysisType
from dotenv import load_dotenv

# LangGraph and LangChain imports
from langgraph.graph import StateGraph, END
from langchain.chat_models import init_chat_model
from langchain.schema import HumanMessage, SystemMessage
from langchain.prompts import ChatPromptTemplate
from langchain.output_parsers import PydanticOutputParser
from pydantic import BaseModel, Field
from os import getenv


# Load environment variables
load_dotenv(Path(__file__).parent / ".env")


class SuspiciousEvent(BaseModel):
    """Pydantic model for suspicious events - compatible with MitreAgentInput format"""
    # Core findings
    detected_anomalies: List[Dict[str, Any]] = Field(description="List of anomalous events/patterns")
    severity: str = Field(description="Severity level: low, medium, high, critical")
    confidence: float = Field(description="Overall confidence score 0.0-1.0", ge=0.0, le=1.0)
    
    # Context
    analysis_type: str = Field(description="Type of analysis performed", default="anomaly_detection")
    time_window: Dict[str, str] = Field(description="Time window of analysis")
    affected_systems: List[str] = Field(description="List of affected hostnames/systems")
    
    # Technical details
    indicators: Dict[str, List[str]] = Field(description="IOCs: ips, domains, file_hashes, etc.")
    event_types: List[str] = Field(description="Types of events detected")
    log_sources: List[str] = Field(description="Sources of log data")
    
    # Additional context
    user_accounts: List[str] = Field(description="Potentially compromised user accounts")
    processes: List[str] = Field(description="Suspicious processes identified")
    network_activity: Dict[str, Any] = Field(description="Network activity patterns")
    file_operations: Dict[str, Any] = Field(description="File operations detected")
    
    # Metadata
    analysis_id: str = Field(description="Unique analysis identifier")
    timestamp: str = Field(description="Analysis timestamp")
    raw_summary: str = Field(description="Natural language summary of findings")




class AnalysisState(TypedDict):
    """State for the LangGraph workflow"""
    raw_events: List[Dict[str, Any]]
    suspicious_events: List[MitreAgentInput]
    analysis_report: Optional[Dict[str, Any]]
    current_batch: List[Dict[str, Any]]
    batch_index: int
    total_events: int
    # Additional fields for MITRE compatibility
    aggregated_findings: Optional[MitreAgentInput]
    analysis_metadata: Dict[str, Any]


class LLMMordorAnalyzer:
    """LLM-powered Mordor log analyzer using LangGraph"""
    
    def __init__(self, dataset_path: str, llm_provider: str = "google"):
        self.dataset_path = Path(dataset_path)
        self.llm_provider = llm_provider
        self.llm = self._initialize_llm()
        
        self.batch_size = 30  # Process events in batches
        self.graph = self._build_graph() # set batch_size config first then build the graph
    def _initialize_llm(self):
        """Initialize the LLM based on provider"""
        if self.llm_provider.lower() == "google":
            return init_chat_model(
                "google_genai:gemini-2.0-flash",
                api_key=getenv("GOOGLE_API_KEY"),
            )
        else:
            raise ValueError(f"Unsupported LLM provider: {self.llm_provider}")
    
    def _build_graph(self) -> Any:
        """Build the LangGraph workflow"""
        workflow = StateGraph(AnalysisState)
        
        # Add nodes
        workflow.add_node("load_data", self.load_data_node)
        workflow.add_node("detect_suspicious", self.detect_suspicious_node)
        workflow.add_node("generate_report", self.generate_report_node)
        
        # Add edges
        workflow.add_edge("load_data", "detect_suspicious")
        workflow.add_edge("detect_suspicious", "generate_report")
        workflow.add_edge("generate_report", END)
        
        # Set entry point
        workflow.set_entry_point("load_data")
        
        return workflow.compile()
    

    def _load_log_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Load events from a single JSON log file"""
        events = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line:
                        try:
                            event = json.loads(line)
                            events.append(event)
                        except json.JSONDecodeError as e:
                            print(f"[WARNING] JSON decode error in {file_path}:{line_num}: {e}")
        except Exception as e:
            print(f"[ERROR] Error reading file {file_path}: {e}")
        return events
    
    def load_data_node(self, state: AnalysisState) -> AnalysisState:
        """Load Mordor logs"""
        print("[INFO] Loading data...")
        
        # Load log events
        events = []
        if self.dataset_path.exists():
            json_files = list(self.dataset_path.glob("*.json"))
            for json_file in json_files:
                events.extend(self._load_log_file(json_file))
        
        print(f"[SUCCESS] Loaded {len(events)} events from {len(json_files)} files")
        
        return {
            **state, #spreads the old state (keeping anything not overwritten).
            "raw_events": events, 
            "suspicious_events": [], #resets suspicious list (start fresh)
            "batch_index": 0, #reset batch counter
            "total_events": len(events)
        }
    
    
    def detect_suspicious_node(self, state: AnalysisState) -> AnalysisState:
        """Use LLM to detect suspicious events with prompt engineering"""
        print("[INFO] Detecting suspicious events with LLM...")
        
        suspicious_events = []
        events = state["raw_events"]
        
        # Process events in batches
        for i in range(0, len(events), self.batch_size):
            batch = events[i:i + self.batch_size]
            batch_suspicious = self._analyze_event_batch(batch)
            suspicious_events.extend(batch_suspicious)
            
            print(f"[INFO] Processed batch {i//self.batch_size + 1}/{(len(events) + self.batch_size - 1)//self.batch_size}")
        
        
        return {
            **state,
            "suspicious_events": suspicious_events
        }
    
    def _analyze_event_batch(self, events: List[Dict[str, Any]]) -> List[MitreAgentInput]:
        """Analyze a batch of events using LLM"""
        
        # Create detection prompt
        detection_prompt = ChatPromptTemplate.from_messages([
            ("system", self._get_detection_system_prompt()),
            ("human", "Analyze these Windows security events for suspicious activity:\n\n{events}")
        ])
        
        # Prepare events for analysis
        events_text = self._format_events_for_llm(events)
        print(f"[DEBUG] Sending {len(events)} events to LLM for analysis")
        
        try:
            # Get LLM response
            response = self.llm.invoke(
                detection_prompt.format_messages(events=events_text)
            )
            
            # print(f"[DEBUG] LLM response type: {type(response.content)}")
            # print(f"[DEBUG] LLM response length: {len(response.content)} characters")
            
            # Parse response to extract suspicious events
            return self._parse_detection_response(response.content, events)
            
        except Exception as e:
            print(f"[ERROR] Error in LLM detection: {e}")
            import traceback
            print(f"[ERROR] Full traceback: {traceback.format_exc()}")
            return []
    
    def _get_detection_system_prompt(self) -> str:
        """System prompt for suspicious event detection"""
        return """You are an expert cybersecurity analyst specializing in Windows event log analysis.

Your task is to identify suspicious activities that may indicate:
- Credential dumping (LSASS access, memory dumps)
- Privilege escalation (token manipulation, privilege enabling)
- Process injection or hollowing
- Lateral movement attempts
- Persistence mechanisms
- Defense evasion techniques

Focus on:
- LSASS.exe access patterns
- Suspicious process names (mimikatz, dumpert, procdump, etc.)
- Privilege escalation (SeDebugPrivilege, SeImpersonatePrivilege)
- Unusual process relationships
- Memory access patterns
- Registry modifications
- Network connections from unexpected processes

CRITICAL: You must respond with ONLY a valid JSON object with this EXACT structure:
{{
  "detected_anomalies": [
    {{
      "id": "anom_001",
      "description": "Clear description of the suspicious activity",
      "timestamp": "2023-01-01T10:30:00Z",
      "confidence": 0.9
    }}
  ],
  "severity": "high",
  "confidence": 0.85,
  "analysis_type": "incident_response",
  "time_window": {{
    "start": "2023-01-01T10:00:00Z",
    "end": "2023-01-01T11:00:00Z"
  }},
  "affected_systems": ["WORKSTATION01"],
  "indicators": {{
    "ips": [],
    "domains": [],
    "file_hashes": [],
    "processes": ["dumpert.exe"],
    "users": ["admin"]
  }},
  "event_types": ["process_creation", "memory_access"],
  "log_sources": ["windows_security", "sysmon"],
  "user_accounts": ["admin"],
  "processes": ["dumpert.exe", "lsass.exe"],
  "network_activity": {{
    "external_connections": 0,
    "unusual_ports": [],
    "data_transfer_gb": 0.0
  }},
  "file_operations": {{
    "created_files": 0,
    "modified_files": 0,
    "deleted_files": 0
  }},
  "analysis_id": "LOG_ANALYSIS_20231027_202412",
  "timestamp": "2023-10-27T20:24:12Z",
  "raw_summary": "SECURITY INCIDENT ANALYSIS REPORT
  
  INCIDENT OVERVIEW:
  Overview of the security incident.
  ATTACK PROGRESSION:
  1. Key step one
  2. Key step two
  TECHNICAL INDICATORS:
  - Indicator A
  - Indicator B
  IMPACT ASSESSMENT:
  - Impact A
  - Impact B
  CLASSIFICATION: Descriptive classification"
}}

Severity levels: "low", "medium", "high", "critical"
Analysis types: "anomaly_detection", "threat_hunting", "incident_response", "compliance_check"

If no suspicious activity is found, return a structure with empty detected_anomalies array and severity "low" but you need to specify why in description, make sure your confidence level reflects your confidence on the analysis.

Do not include any explanatory text, markdown formatting, or code blocks. Return only the JSON object."""
    
    def _format_events_for_llm(self, events: List[Dict[str, Any]]) -> str:
        """Format events for LLM analysis"""
        formatted_events = []
        for i, event in enumerate(events[:20]):  # Limit to prevent token overflow
            # Extract key fields for analysis
            key_fields = {
                "EventID": event.get("EventID"),
                "TimeCreated": event.get("TimeCreated"),
                "Hostname": event.get("Hostname"),
                "ProcessName": event.get("ProcessName"),
                "CommandLine": event.get("CommandLine"),
                "ObjectName": event.get("ObjectName"),
                "AccessMask": event.get("AccessMask"),
                "AccessList": event.get("AccessList"),
                "EnabledPrivilegeList": event.get("EnabledPrivilegeList"),
                "SubjectUserName": event.get("SubjectUserName"),
                "TargetUserName": event.get("TargetUserName")
            }
            # Remove None values
            key_fields = {k: v for k, v in key_fields.items() if v is not None}
            formatted_events.append(f"Event {i+1}: {json.dumps(key_fields, indent=2)}")
        
        return "\n\n".join(formatted_events)
    
    def _parse_detection_response(self, response: str, original_events: List[Dict[str, Any]]) -> List[MitreAgentInput]:
        """Parse LLM response to extract suspicious events in new MitreAgentInput format"""
        # print(f"[DEBUG] Raw LLM response: {response[:500]}...")  # Show first 500 chars for debugging
        
        try:
            # Try multiple JSON extraction methods
            import re
            from datetime import datetime
            
            # Method 1: Try to find JSON between code blocks first (most common)
            code_block_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
            if code_block_match:
                json_text = code_block_match.group(1)
                # print(f"[DEBUG] Extracted JSON from code block: {json_text[:500]}...")
                analysis_data = json.loads(json_text)
            else:
                # Method 2: Look for JSON object without code blocks
                json_match = re.search(r'\{.*?\}', response, re.DOTALL)
                if json_match:
                    json_text = json_match.group()
                    print(f"[DEBUG] Extracted JSON: {json_text[:200]}...")
                    analysis_data = json.loads(json_text)
                else:
                    # Method 3: Try to parse the entire response as JSON
                    print("[DEBUG] Attempting to parse entire response as JSON")
                    analysis_data = json.loads(response.strip())
            
            if not isinstance(analysis_data, dict):
                print(f"[WARNING] Expected JSON object, got {type(analysis_data)}")
                return []
            
            print(f"[DEBUG] Successfully parsed analysis data from LLM response")
            
            # Generate timestamps if missing
            current_time = datetime.now().isoformat()
            if not analysis_data.get('timestamp'):
                analysis_data['timestamp'] = current_time
            # Sanitize or generate analysis_id
            analysis_id_raw = analysis_data.get('analysis_id')
            if not analysis_id_raw or '+' in str(analysis_id_raw):
                analysis_data['analysis_id'] = f"LOG_ANALYSIS_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Ensure time_window is properly formatted
            if not analysis_data.get('time_window'):
                analysis_data['time_window'] = {"start": current_time, "end": current_time}
            

            # Create a single SuspiciousEvent object with the complete analysis
            suspicious_event = MitreAgentInput(
                detected_anomalies=analysis_data.get('detected_anomalies', []),
                severity=SeverityLevel(analysis_data.get('severity', 'low').lower()),
                confidence=float(analysis_data.get('confidence', 0.5)),
                analysis_type=AnalysisType(analysis_data.get('analysis_type', 'anomaly_detection')),
                time_window=analysis_data.get('time_window'),
                affected_systems=analysis_data.get('affected_systems', []),
                indicators=analysis_data.get('indicators', {"ips": [], "domains": [], "file_hashes": []}),
                event_types=analysis_data.get('event_types', ["security_event"]),
                log_sources=analysis_data.get('log_sources', ["windows_security"]),
                user_accounts=analysis_data.get('user_accounts', []),
                processes=analysis_data.get('processes', []),
                network_activity=analysis_data.get('network_activity', {}),
                file_operations=analysis_data.get('file_operations', {}),
                analysis_id=analysis_data.get('analysis_id'),
                timestamp=analysis_data.get('timestamp'),
                raw_summary=analysis_data.get('raw_summary', 'Analysis completed')
            )
            
            print(f"[DEBUG] Created suspicious event with {len(suspicious_event.detected_anomalies)} anomalies")
            return [suspicious_event]
            
        except json.JSONDecodeError as e:
            print(f"[ERROR] JSON decode error: {e}")
            print(f"[ERROR] Response content: {response}")
        except Exception as e:
            print(f"[ERROR] Error parsing LLM response: {e}")
            print(f"[ERROR] Response content: {response}")
        
        # Fallback: Create mock events to test the pipeline
        print("[WARNING] Creating fallback mock events for testing")
        if original_events:
            from datetime import datetime
            current_time = datetime.now().isoformat()
            
            # Create a fallback SuspiciousEvent in the new format
            mock_event = MitreAgentInput(
                detected_anomalies=[
                    {
                        "id": "fallback_001",
                        "description": "LLM parsing failed - fallback event created",
                        "timestamp": current_time,
                        "confidence": 0.5
                    }
                ],
                severity=SeverityLevel.MEDIUM,
                confidence=0.5,
                analysis_type=AnalysisType.ANOMALY_DETECTION,
                time_window={"start": current_time, "end": current_time},
                affected_systems=[original_events[0].get("Hostname", "Unknown")],
                indicators={"ips": [], "domains": [], "file_hashes": [], "processes": [], "users": []},
                event_types=["parsing_error"],
                log_sources=["windows_security"],
                user_accounts=[],
                processes=[],
                network_activity={"external_connections": 0, "unusual_ports": [], "data_transfer_gb": 0.0},
                file_operations={"created_files": 0, "modified_files": 0, "deleted_files": 0},
                analysis_id=f"FALLBACK_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                timestamp=current_time,
                raw_summary="LLM parsing failed, fallback event created for testing"
            )
            return [mock_event]
        
        return []

    
    def generate_report_node(self, state: AnalysisState) -> AnalysisState:
        """Return ONLY the MitreAgentInput JSON object (first detected event)."""
        print("[INFO] Preparing final MitreAgentInput output...")
        
        suspicious_events = state["suspicious_events"]
        
        # Take the first suspicious event as representative (or empty fallback).
        
        if suspicious_events:
            ev = suspicious_events[0]
            report = {**asdict(ev), "severity": ev.severity.value, "analysis_type": ev.analysis_type.value}
        else:
            report = {}
        
        return {
            **state,
            "analysis_report": report
        }
    

    async def analyze(self) -> Dict[str, Any]:
        """Run the complete analysis workflow"""
        print("[START] Starting LLM-based Mordor log analysis...")
        
        initial_state = AnalysisState(
            raw_events=[],
            suspicious_events=[],
            analysis_report=None,
            current_batch=[],
            batch_index=0,
            total_events=0
        )
        
        # Execute the graph
        final_state = await self.graph.ainvoke(initial_state)
        
        print("[SUCCESS] Analysis complete!")
        return final_state["analysis_report"]
    
    def print_summary(self, report: Dict[str, Any]) -> None:
        """Print the final MitreAgentInput JSON"""
        print("\n" + "="*80)
        print("[REPORT] LOG ANALYSIS OUTPUT TO MITRE AGENT")
        print("="*80)
        
        print(json.dumps(report, indent=2))
        print("="*80)
        return


def main():
    """Main execution function"""
    import asyncio
    
    # Paths relative to the script location
    script_dir = Path(__file__).parent
    dataset_path = script_dir / "mordor_dataset_test"
    
    # Initialize LLM analyzer
    analyzer = LLMMordorAnalyzer(
        str(dataset_path),
        llm_provider="google"  # Using Google Gemini
    )
    
    # Run analysis
    async def run_analysis():
        report = await analyzer.analyze()
        
        # Print summary
        analyzer.print_summary(report)
        
        # Save detailed report
        output_file = script_dir / "llm_analysis_report.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        print(f"\n[SAVED] Detailed report saved to: {output_file}")
        
        return report
    
    # Run the async analysis
    return asyncio.run(run_analysis())


if __name__ == "__main__":
    main()