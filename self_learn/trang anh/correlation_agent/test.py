from dotenv import load_dotenv
load_dotenv()

from src.agents.correlation_agent.correlation_logic import CorrelationAgent
from src.agents.correlation_agent.types import LogInput, MitreInput
from src.agents.mitre_retriever_agent.mitre_example_input import create_sample_log_input, create_elaborate_mockup_incident
from src.agents.mitre_retriever_agent.mitre_agent import MitreAgent
from src.agents.correlation_agent.input_converters import convert_mitre_agent_input, convert_mitre_analysis_output

def test_sample_correlation():
    """Test basic correlation functionality using real MITRE agent output"""
    print("="*60)
    print("TESTING BASIC CORRELATION WITH MITRE AGENT")
    print("="*60)
    
    # Create sample input from mitre_example_input
    mitre_agent_input = create_sample_log_input()
    log_input = convert_mitre_agent_input(mitre_agent_input)
    
    print(f"\nSAMPLE INPUT CREATED:")
    print(f"- Analysis ID: {log_input.analysis_id}")
    print(f"- Severity: {log_input.severity}")
    print(f"- Affected Systems: {log_input.affected_systems}")
    print(f"- Anomalies: {len(log_input.anomalies)} detected")
    print(f"- Processes: {log_input.processes}")
    
    print("\nRUNNING MITRE AGENT ANALYSIS...")
    mitre_agent = MitreAgent(
        llm_provider="openai",
        model_name="gpt-4o",
        max_iterations=3
    )
    
    mitre_analysis_result = mitre_agent.analyze_threat(mitre_agent_input)
    print(f"✓ MITRE analysis completed")
    print(f"  - Techniques found: {len(mitre_analysis_result.get('technique_details', []))}")
    print(f"  - Coverage score: {mitre_analysis_result.get('coverage_score', 0):.3f}")
    print(f"  - Confidence: {mitre_analysis_result.get('confidence', 0):.3f}")
    
    # Convert MITRE analysis to MitreInput format
    mitre_input = convert_mitre_analysis_output(mitre_analysis_result, mitre_agent_input)
    
    print(f"\n✓ MITRE INPUT CONVERTED:")
    print(f"  - Top {min(5, len(mitre_input.techniques))} techniques:")
    for i, tech in enumerate(mitre_input.techniques[:5], 1):
        print(f"    {i}. {tech['attack_id']}: {tech['name']} (Score: {tech['relevance_score']:.3f})")
    
    # Run correlation analysis
    print("\nRUNNING CORRELATION ANALYSIS...")
    correlation_agent = CorrelationAgent()
    result = correlation_agent.process(log_input, mitre_input)
    
    # Display results
    print(f"\n{'='*60}")
    print(f"CORRELATION RESULTS:")
    print(f"{'='*60}")
    print(f"ID: {result.correlation_id}")
    print(f"Score: {result.correlation_score:.3f}")
    print(f"Threat Level: {result.threat_level.value.upper()}")
    print(f"Confidence: {result.confidence.value.upper()}")
    print(f"Timestamp: {result.timestamp}")
    
    print(f"\nMATCHED TECHNIQUES ({len(result.matched_techniques)}):")
    for i, tech in enumerate(result.matched_techniques, 1):
        print(f"{i}. {tech.technique_id} - Confidence: {tech.match_confidence:.3f}")
        print(f"   Evidence: {tech.evidence[:100]}{'...' if len(tech.evidence) > 100 else ''}")
    
    print(f"\nREASONING:")
    print(f"{result.reasoning}")
    
    return result

def test_elaborate_correlation():
    """Test correlation using elaborate mockup incident with MITRE agent"""
    print("\n" + "="*60)
    print("TESTING CORRELATION - ELABORATE INCIDENT")
    print("="*60)
    
    # Create elaborate incident input
    mitre_agent_input = create_elaborate_mockup_incident()
    log_input = convert_mitre_agent_input(mitre_agent_input)
    
    print(f"\nELABORATE INCIDENT INPUT:")
    print(f"- Analysis ID: {log_input.analysis_id}")
    print(f"- Severity: {log_input.severity}")
    print(f"- Affected Systems: {len(log_input.affected_systems)} systems")
    print(f"- Anomalies: {len(log_input.anomalies)} detected")
    print(f"- Processes: {len(log_input.processes)} processes")
    
    # Run MITRE agent analysis for elaborate incident
    print("\nRUNNING MITRE AGENT ANALYSIS FOR ELABORATE INCIDENT...")
    mitre_agent = MitreAgent(
        llm_provider="openai",
        model_name="gpt-4o",
        max_iterations=3
    )
    
    mitre_analysis_result = mitre_agent.analyze_threat(mitre_agent_input)
    print(f"✓ MITRE analysis completed")
    print(f"  - Techniques found: {len(mitre_analysis_result.get('technique_details', []))}")
    print(f"  - Coverage score: {mitre_analysis_result.get('coverage_score', 0):.3f}")
    print(f"  - Confidence: {mitre_analysis_result.get('confidence', 0):.3f}")
    
    # Convert to MitreInput
    mitre_input = convert_mitre_analysis_output(mitre_analysis_result, mitre_agent_input)
    
    print(f"\n✓ TOP TECHNIQUES FROM MITRE ANALYSIS:")
    for i, tech in enumerate(mitre_input.techniques[:5], 1):
        print(f"  {i}. {tech['attack_id']}: {tech['name'][:50]}... (Score: {tech['relevance_score']:.3f})")
    
    # Run correlation analysis
    print("\nRUNNING ELABORATE CORRELATION ANALYSIS...")
    correlation_agent = CorrelationAgent()
    result = correlation_agent.process(log_input, mitre_input)

    print(f"\n{'='*60}")
    print(f"ELABORATE CORRELATION RESULTS:")
    print(f"{'='*60}")
    print(f"ID: {result.correlation_id}")
    print(f"Score: {result.correlation_score:.3f}")
    print(f"Threat Level: {result.threat_level.value.upper()}")
    print(f"Confidence: {result.confidence.value.upper()}")
    print(f"Matched Techniques: {len(result.matched_techniques)}")
    
    print(f"\nTOP CORRELATED TECHNIQUES:")
    for i, tech in enumerate(result.matched_techniques[:5], 1):
        print(f"{i}. {tech.technique_id} - Confidence: {tech.match_confidence:.3f}")
        print(f"   Evidence: {tech.evidence[:80]}{'...' if len(tech.evidence) > 80 else ''}")
    
    print(f"\nREASONING:")
    print(f"{result.reasoning}")
    
    return result

def main():
    """Main test function"""
    print("╔" + "="*58 + "╗")
    print("║" + " "*10 + "CORRELATION AGENT TEST SUITE" + " "*20 + "║")
    print("╚" + "="*58 + "╝")
    print()
    
    try:
        # Test sample correlation with MITRE agent
        result1 = test_sample_correlation()

        # Test elaborate correlation with elaborate incident
        result2 = test_elaborate_correlation()

        print("\n" + "="*60)
        print("✓ ALL TESTS COMPLETED SUCCESSFULLY")
        print("="*60)
        
        # Summary
        print(f"\nTEST SUMMARY:")
        print(f"\n1. Sample Input Test:")
        print(f"   - Threat Level: {result1.threat_level.value.upper()}")
        print(f"   - Confidence: {result1.confidence.value.upper()}")
        print(f"   - Correlation Score: {result1.correlation_score:.3f}")
        print(f"   - Matched Techniques: {len(result1.matched_techniques)}")
        
        print(f"\n2. Elaborate Incident Test:")
        print(f"   - Threat Level: {result2.threat_level.value.upper()}")
        print(f"   - Confidence: {result2.confidence.value.upper()}")
        print(f"   - Correlation Score: {result2.correlation_score:.3f}")
        print(f"   - Matched Techniques: {len(result2.matched_techniques)}")
        
        print("\n" + "="*60)
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    main()