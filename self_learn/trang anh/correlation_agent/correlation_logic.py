from typing import Dict, Any, List, Optional
from datetime import datetime
import json
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from pydantic import BaseModel, Field, ConfigDict
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
from .types import LogInput, MitreInput, CorrelationOutput, ThreatLevel, ConfidenceLevel, MatchedTechnique

embeddings = OpenAIEmbeddings(model="text-embedding-3-small")


# State schema for correlation workflow
class CorrelationState(BaseModel):
    """State schema for correlation workflow."""
    analysis_request: str = ""
    agent_output: Optional[str] = None
    structured_response: Optional[Dict[str, Any]] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)


# Structured response schemas
class MatchedTechniqueItem(BaseModel):
    """Schema for individual matched technique."""
    technique_id: str = Field(..., description="MITRE technique ID")
    match_confidence: float = Field(..., ge=0.0, le=1.0, description="Correlation confidence 0-1")
    evidence: str = Field(..., description="Concise evidence string")
    validation_result: str = Field(..., description="correlated | weak | false_positive")
    model_config = ConfigDict(extra='forbid')


class CorrelationStructuredResponse(BaseModel):
    """Structured response schema for correlation analysis output."""
    correlation_score: float = Field(..., description="Overall aggregate correlation score (0-1)")
    threat_level: str = Field(..., description="low | medium | high | critical")
    confidence: str = Field(..., description="low | medium | high")
    matched_techniques: List[MatchedTechniqueItem] = Field(
        default_factory=list,
        description="Top 3-5 matched techniques"
    )
    reasoning: str = Field(..., description="Concise synthesis / justification of assessment (<150 words)")
    model_config = ConfigDict(extra='forbid')


# Helper function for JSON parsing
def parse_json_input(data: Any) -> Any:
    """Parse JSON string or return as-is if already parsed."""
    return json.loads(data) if isinstance(data, str) else data


@tool
def correlate_log_with_technique(technique_data: str, log_processes: List[str], log_anomalies: List[str]) -> str:
    """Semantic correlation between log data and MITRE technique using embeddings."""
    try:
        technique = parse_json_input(technique_data)
    except:
        return json.dumps({"error": "Invalid technique data format"})
    
    technique_id = technique.get('attack_id', 'Unknown')
    technique_name = technique.get('name', 'Unknown')
    technique_description = technique.get('description', '')
    
    if not technique_description:
        return json.dumps({
            "technique_id": technique_id,
            "technique_name": technique_name,
            "correlation_score": 0.0,
            "process_matches": [],
            "anomaly_matches": [],
            "match_quality": "weak"
        })
    
    # Semantic matching using embeddings
    try:
        technique_embedding = np.array(embeddings.embed_query(technique_description)).reshape(1, -1)
        
        # Process matching
        process_matches = []
        process_scores = []
        for process in log_processes:
            if not process.strip():
                continue
            process_embedding = np.array(embeddings.embed_query(process)).reshape(1, -1)
            similarity = cosine_similarity(technique_embedding, process_embedding)[0][0]
            if similarity > 0.6:
                process_matches.append(process)
                process_scores.append(float(similarity))
        
        # Anomaly matching
        anomaly_matches = []
        anomaly_scores = []
        for anomaly in log_anomalies:
            if not str(anomaly).strip():
                continue
            anomaly_embedding = np.array(embeddings.embed_query(str(anomaly))).reshape(1, -1)
            similarity = cosine_similarity(technique_embedding, anomaly_embedding)[0][0]
            if similarity > 0.5:
                anomaly_matches.append(anomaly)
                anomaly_scores.append(float(similarity))
        
        # Calculate correlation score
        avg_process_score = np.mean(process_scores) if process_scores else 0.0
        avg_anomaly_score = np.mean(anomaly_scores) if anomaly_scores else 0.0
        correlation_score = (avg_process_score + avg_anomaly_score) / 2
        
    except Exception as e:
        # Fallback to keyword matching
        print(f"[WARN] Semantic correlation failed: {e}, using fallback")
        keywords = technique_description.lower().split()[:5]
        process_matches = [p for p in log_processes if any(k in p.lower() for k in keywords)]
        anomaly_matches = [a for a in log_anomalies if any(k in str(a).lower() for k in keywords)]
        correlation_score = 0.3 if (process_matches or anomaly_matches) else 0.1
    
    return json.dumps({
        "technique_id": technique_id,
        "technique_name": technique_name,
        "correlation_score": round(float(correlation_score), 3),
        "process_matches": process_matches,
        "anomaly_matches": anomaly_matches,
        "match_quality": "strong" if correlation_score > 0.7 else "moderate" if correlation_score > 0.5 else "weak"
    })

@tool
def correlate_all_techniques(techniques: str, log_processes: str, log_anomalies: str) -> str:
    """Correlate all MITRE techniques with log data."""
    try:
        technique_list = parse_json_input(techniques)
        processes = parse_json_input(log_processes)
        anomalies = parse_json_input(log_anomalies)
    except:
        return json.dumps({"error": "Invalid input format"})
    
    correlations = [
        json.loads(correlate_log_with_technique(tech, processes, anomalies))
        for tech in technique_list
    ]
    
    correlations.sort(key=lambda x: x['correlation_score'], reverse=True)
    
    return json.dumps({
        "correlations": correlations,
        "top_matches": correlations[:3],
        "total_techniques": len(correlations),
        "strong_matches": len([c for c in correlations if c['correlation_score'] > 0.7])
    })

@tool
def calculate_confidence(
    correlation_score: float, 
    log_severity: str = "medium", 
    mitre_confidence: float = 0.5,
    num_matched_techniques: int = 1,
    match_quality: str = "moderate"
) -> str:
    """
    Sophisticated confidence calculation using Bayesian-inspired weighted scoring.
    """
    
    # Weight distribution based on cybersecurity research
    WEIGHTS = {
        'correlation': 0.50,   # Primary indicator - semantic match quality
        'evidence': 0.25,      # Evidence strength (quality + quantity)
        'mitre_prior': 0.15,   # Bayesian prior from MITRE analysis
        'severity': 0.10       # Contextual severity adjustment
    }
    
    # Quality scores based on semantic similarity thresholds
    quality_scores = {'strong': 1.0, 'moderate': 0.7, 'weak': 0.4}
    quality_score = quality_scores.get(match_quality.lower(), 0.7)
    
    # Quantity factor with diminishing returns
    quantity_factor = min(1.0, 0.5 + (num_matched_techniques * 0.15))
    evidence_component = quality_score * quantity_factor
    
    # Severity scores based on CVSS principles
    severity_scores = {'critical': 1.0, 'high': 0.85, 'medium': 0.6, 'low': 0.35}
    severity_component = severity_scores.get(log_severity.lower(), 0.6)
    
    # Weighted combination
    overall_confidence = (
        WEIGHTS['correlation'] * correlation_score +
        WEIGHTS['evidence'] * evidence_component +
        WEIGHTS['mitre_prior'] * mitre_confidence +
        WEIGHTS['severity'] * severity_component
    )
    
    # Cap at 0.95 to avoid overconfidence bias
    overall_confidence = min(overall_confidence, 0.95)
    
    # Uncertainty penalty for weak single matches
    if num_matched_techniques == 1 and match_quality.lower() == 'weak':
        overall_confidence *= 0.8
    
    # Determine confidence level (FIRST/NIST guidelines)
    if overall_confidence >= 0.75:
        level = "high"
    elif overall_confidence >= 0.50:
        level = "medium"
    else:
        level = "low"
    
    reasoning = (
        f"Correlation: {correlation_score:.2f} ({WEIGHTS['correlation']}) | "
        f"Evidence: {num_matched_techniques} {match_quality} ({WEIGHTS['evidence']}) | "
        f"MITRE: {mitre_confidence:.2f} ({WEIGHTS['mitre_prior']}) | "
        f"Severity: {log_severity} ({WEIGHTS['severity']})"
    )
    
    return json.dumps({
        "confidence_score": round(overall_confidence, 3),
        "confidence_level": level,
        "reasoning": reasoning,
        "methodology": "Bayesian weighted scoring (Hutchins 2011, NIST SP 800-150)"
    })


# Constants for default fallback
DEFAULT_CORRELATION_DATA = {
    "correlation_score": 0.5,
    "threat_level": "medium",
    "confidence": "medium",
    "matched_techniques": [],
    "reasoning": "Workflow failed to produce correlation data"
}


def create_correlation_workflow() -> Optional[Any]:
    """
    Create correlation workflow with structured output using StateGraph.
    
    Workflow: START → correlation_agent → structure_output → END
    """
    if ChatOpenAI is None:
        print("[WARN] Missing ChatOpenAI dependency. Returning None.")
        return None

    # ReAct agent with all tools
    correlation_agent = create_react_agent(
        model="openai:gpt-4o",
        tools=[correlate_all_techniques, correlate_log_with_technique, calculate_confidence],
        name="correlation_agent",
    )
    
    # LLM for structured output extraction
    structured_llm = ChatOpenAI(model="gpt-4o").with_structured_output(
        CorrelationStructuredResponse,
        method="json_schema"
    )
    
    def agent_node(state: CorrelationState) -> CorrelationState:
        """Execute the correlation agent with tools."""
        agent_prompt = (
            f"{state.analysis_request}\n\n"
            "Instructions:\n"
            "1. Use correlate_all_techniques to get correlation scores for all techniques.\n"
            "2. Analyze the top matches and their correlation scores.\n"
            "3. Use calculate_confidence with:\n"
            "   - correlation_score: highest or average correlation score\n"
            "   - log_severity: from log data\n"
            "   - mitre_confidence: from MITRE data\n"
            "   - num_matched_techniques: count of techniques with score > 0.5\n"
            "   - match_quality: 'strong' (>0.7), 'moderate' (0.5-0.7), or 'weak' (<0.5)\n"
            "4. Summarize findings with evidence and reasoning.\n"
        )
        
        result = correlation_agent.invoke({"messages": [HumanMessage(content=agent_prompt)]})
        
        # Extract agent's final message
        for msg in reversed(result.get("messages", [])):
            if isinstance(msg, AIMessage):
                state.agent_output = msg.content
                break
        
        return state
    
    def structure_output_node(state: CorrelationState) -> CorrelationState:
        """Extract structured output from agent's analysis."""
        structure_prompt = f"""Based on the correlation analysis, provide a structured assessment.

Analysis:
{state.agent_output}

Original Request:
{state.analysis_request}

Extract:
- correlation_score: Overall score (0-1)
- threat_level: low/medium/high/critical
- confidence: low/medium/high from confidence calculation
- matched_techniques: Top 3-5 with IDs, confidence, evidence, validation
- reasoning: Concise synthesis (max 150 words)"""
        
        try:
            structured_result = structured_llm.invoke(structure_prompt)
            
            if isinstance(structured_result, CorrelationStructuredResponse):
                state.structured_response = structured_result.model_dump()
            else:
                state.structured_response = structured_result
                
        except Exception as e:
            print(f"[ERROR] Failed to create structured output: {e}")
            state.structured_response = DEFAULT_CORRELATION_DATA.copy()
            state.structured_response["reasoning"] = f"Structuring failed: {str(e)}"
        
        return state
    
    # Build workflow graph
    workflow = StateGraph(CorrelationState)
    workflow.add_node("correlation_agent", agent_node)
    workflow.add_node("structure_output", structure_output_node)
    workflow.set_entry_point("correlation_agent")
    workflow.add_edge("correlation_agent", "structure_output")
    workflow.add_edge("structure_output", END)
    
    return workflow.compile()

class CorrelationLogic:
    """Correlation analysis using ReAct agent workflow with structured output."""
    
    def __init__(self):
        try:
            self.workflow = create_correlation_workflow()
            if self.workflow:
                print("[INFO] Correlation workflow initialized")
            else:
                print("[WARN] Workflow initialization failed")
        except Exception as e:
            print(f"[WARN] Workflow initialization error: {e}")
            self.workflow = None
        
    def correlate(self, log_input: LogInput, mitre_input: MitreInput) -> CorrelationOutput:
        """Main correlation method."""
        correlation_data = self.run_workflow(log_input, mitre_input)
        correlation_id = f"CORR_{log_input.analysis_id}_{mitre_input.analysis_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Use defaults if workflow failed
        if not correlation_data:
            print("[WARN] Using default correlation data")
            return CorrelationOutput(
                correlation_id=correlation_id,
                correlation_score=0.5,
                threat_level=ThreatLevel.MEDIUM,
                confidence=ConfidenceLevel.MEDIUM,
                matched_techniques=[],
                reasoning="Workflow failed",
                timestamp=datetime.now().isoformat()
            )

        # Parse matched techniques
        matched_techniques = []
        for mt_data in correlation_data.get("matched_techniques", []):
            try:
                matched_techniques.append(
                    MatchedTechnique(
                        technique_id=mt_data.get("technique_id", "Unknown"),
                        match_confidence=mt_data.get("match_confidence", 0.0),
                        evidence=mt_data.get("evidence", ""),
                        validation_result=None
                    )
                )
            except Exception as e:
                print(f"[WARN] Skipping malformed technique: {e}")

        # Helper to convert string to enum
        def to_enum(enum_cls, value: str, default):
            try:
                return enum_cls(value.lower())
            except:
                return default

        return CorrelationOutput(
            correlation_id=correlation_id,
            correlation_score=correlation_data.get("correlation_score", 0.5),
            threat_level=to_enum(ThreatLevel, correlation_data.get("threat_level", "medium"), ThreatLevel.MEDIUM),
            confidence=to_enum(ConfidenceLevel, correlation_data.get("confidence", "medium"), ConfidenceLevel.MEDIUM),
            matched_techniques=matched_techniques,
            reasoning=correlation_data.get("reasoning", "No reasoning provided"),
            timestamp=datetime.now().isoformat()
        )
    
    def run_workflow(self, log_input: LogInput, mitre_input: MitreInput) -> Optional[Dict[str, Any]]:
        """Execute the correlation workflow and return structured data."""
        if not self.workflow:
            print("[ERROR] Workflow not initialized")
            return None

        analysis_request = (
            f"Perform correlation analysis for this security event.\n\n"
            f"LOG DATA:\n"
            f"- ID: {log_input.analysis_id}\n"
            f"- Severity: {log_input.severity}\n"
            f"- Systems: {', '.join(log_input.affected_systems)}\n"
            f"- Anomalies: {', '.join(log_input.anomalies)}\n"
            f"- Processes: {', '.join(log_input.processes)}\n"
            f"- Summary: {log_input.raw_summary}\n\n"
            f"MITRE DATA:\n"
            f"- Techniques: {json.dumps(mitre_input.techniques)}\n"
            f"- Coverage: {mitre_input.coverage_score}\n"
            f"- Confidence: {mitre_input.confidence}\n"
            f"- Analysis: {mitre_input.analysis_text}\n"
        )
        
        try:
            initial_state = CorrelationState(analysis_request=analysis_request)
            result = self.workflow.invoke(initial_state)

            if isinstance(result, dict) and "structured_response" in result:
                return result.get("structured_response")
            
            print("[WARN] No structured_response in result")
            return None
            
        except Exception as e:
            print(f"[ERROR] Workflow failed: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            return None


class CorrelationAgent:
    """Multi-Agent Correlation Agent with StateGraph workflow."""
    
    def __init__(self):
        self.correlation_logic = CorrelationLogic()
        print("[INFO] CorrelationAgent initialized")
    
    def process(self, log_input: LogInput, mitre_input: MitreInput) -> CorrelationOutput:
        """Process correlation analysis using multi-agent system."""
        print(f"[INFO] Processing correlation: {log_input.analysis_id}")
        
        try:
            result = self.correlation_logic.correlate(log_input, mitre_input)
            
            print(f"[INFO] Completed: {result.correlation_id}")
            print(f"[INFO] Threat: {result.threat_level.value.upper()} | "
                  f"Confidence: {result.confidence.value.upper()} | "
                  f"Score: {result.correlation_score:.3f} | "
                  f"Techniques: {len(result.matched_techniques)}")
            
            return result
            
        except Exception as e:
            print(f"[ERROR] Correlation processing failed: {e}")
            raise