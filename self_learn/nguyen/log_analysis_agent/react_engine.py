import json
import time
from langchain_core.messages import HumanMessage
from langgraph.prebuilt import create_react_agent
from langchain_core.tools import tool

from state_models import AnalysisState
from utils import get_llm, get_tools, format_execution_time
from prompts import ANALYSIS_PROMPT, CRITIC_FEEDBACK_TEMPLATE
from criticism_engine import self_critic_review

def react_agent_analysis(state: AnalysisState):
    """Perform ReAct agent analysis with iterative refinement"""
    print("Starting ReAct agent analysis with iterative refinement...")
    
    # Get base tools
    base_tools = get_tools()
    
    # Create state-aware event_id_extractor
    @tool
    def event_id_extractor_with_logs(suspected_event_id: str) -> dict:
        """Validates and corrects Windows Event IDs identified in log analysis."""
        from tools.event_id_extractor_tool import _event_id_extractor_tool
        return _event_id_extractor_tool.run({
            "suspected_event_id": suspected_event_id,
            "raw_logs": state["raw_logs"]
        })
    
    # Create state-aware timeline_builder
    @tool
    def timeline_builder_with_logs(pivot_entity: str, pivot_type: str, time_window_minutes: int = 5) -> dict:
        """Build a focused timeline around suspicious events to understand attack sequences.
        
        Use this when you suspect coordinated activity or want to understand what happened 
        before and after a suspicious event. Analyzes the sequence of events to identify patterns.
        
        Args:
            pivot_entity: The entity to build timeline around (e.g., "powershell.exe", "admin", "192.168.1.100")
            pivot_type: Type of entity - "user", "process", "ip", "file", "computer", "event_id", or "registry"
            time_window_minutes: Minutes before and after pivot events to include (default: 5)
        
        Returns:
            Timeline analysis showing events before and after the pivot, helping identify attack sequences.
        """
        from tools.timeline_builder_tool import _timeline_builder_tool
        return _timeline_builder_tool.run({
            "pivot_entity": pivot_entity,
            "pivot_type": pivot_type,
            "time_window_minutes": time_window_minutes,
            "raw_logs": state["raw_logs"]
        })
    
    # Replace base tools with state-aware versions
    tools = [t for t in base_tools if t.name not in ["event_id_extractor", "timeline_builder"]]
    tools.append(event_id_extractor_with_logs)
    tools.append(timeline_builder_with_logs)
    
    # Create ReAct agent
    llm = get_llm()
    agent_executor = create_react_agent(llm, tools)
    
    # System context
    system_context = """You are Agent A, an autonomous cybersecurity analyst.

IMPORTANT CONTEXT - RAW LOGS AVAILABLE:
The complete raw logs are available for certain tools automatically.
When you call event_id_extractor_with_logs or timeline_builder_with_logs, 
you only need to provide the required parameters - the tools will automatically 
access the raw logs to perform their analysis.

"""
    
    # Maximum iterations
    MAX_ITERATIONS = 2
    
    try:
        # Iterative refinement loop
        for iteration in range(MAX_ITERATIONS):
            state["iteration_count"] = iteration
            print(f"\n{'='*60}")
            print(f"ITERATION {iteration + 1}/{MAX_ITERATIONS}")
            print(f"{'='*60}")
            
            # Prepare prompt with optional feedback
            if iteration == 0:
                # First iteration - no feedback
                critic_feedback_section = ""
                full_prompt = system_context + ANALYSIS_PROMPT.format(
                    logs=state["prepared_logs"],
                    critic_feedback_section=critic_feedback_section
                )
                messages = [HumanMessage(content=full_prompt)]
            else:
                # Subsequent iterations - include feedback and preserve messages
                critic_feedback_section = CRITIC_FEEDBACK_TEMPLATE.format(
                    iteration=iteration + 1,
                    feedback=state["critic_feedback"]
                )
                # ONLY COPY LANGCHAIN MESSAGE OBJECTS, NOT DICTS
                messages = [msg for msg in state["messages"] if not isinstance(msg, dict)]
                messages.append(HumanMessage(content=critic_feedback_section))
            
            # Run ReAct agent
            print(f"Running agent analysis...")
            result = agent_executor.invoke({"messages": messages})
            state["messages"] = result["messages"]
            
            # Extract and process final analysis
            final_analysis = _extract_final_analysis(state["messages"])
            
            # Calculate execution time
            state["end_time"] = time.time()
            execution_time = format_execution_time(state["end_time"] - state["start_time"])
            
            # Extract reasoning
            state["agent_reasoning"] = final_analysis.get("reasoning", "")
            
            # Format result
            state["analysis_result"] = _format_analysis_result(
                final_analysis, execution_time, iteration + 1, state["agent_reasoning"]
            )
            
            # Run self-critic review
            print("Running self-critic review...")
            original_analysis = state["analysis_result"].copy()
            critic_result = self_critic_review(llm, state)
            
            # Store iteration in history
            state["iteration_history"].append({
                "iteration": iteration + 1,
                "original_analysis": original_analysis,
                "critic_evaluation": {
                    "quality_acceptable": critic_result["quality_acceptable"],
                    "issues": critic_result["issues"],
                    "feedback": critic_result["feedback"]
                },
                "corrected_analysis": critic_result["corrected_analysis"]
            })
            
            # Use corrected analysis
            corrected = critic_result["corrected_analysis"]
            corrected["execution_time_seconds"] = original_analysis.get("execution_time_seconds", 0)
            corrected["execution_time_formatted"] = original_analysis.get("execution_time_formatted", "Unknown")
            corrected["iteration_count"] = iteration + 1
            state["analysis_result"] = corrected
            
            # Check if refinement is needed
            if critic_result["quality_acceptable"]:
                print(f"✓ Quality acceptable - stopping at iteration {iteration + 1}")
                break
            elif iteration < MAX_ITERATIONS - 1:
                print(f"✗ Quality needs improvement - proceeding to iteration {iteration + 2}")
                state["critic_feedback"] = critic_result["feedback"]
            else:
                print(f"✗ Max iterations reached - using current analysis")
        
        print(f"\nAnalysis complete after {state['iteration_count']} iteration(s)")
        print(f"Total messages: {len(state['messages'])}")
        
    except Exception as e:
        print(f"Error in analysis: {e}")
        import traceback
        traceback.print_exc()
        state["end_time"] = time.time()
        execution_time = format_execution_time(state["end_time"] - state["start_time"])
        
        state["analysis_result"] = {
            "overall_assessment": "ERROR",
            "total_events_analyzed": 0,
            "execution_time_seconds": execution_time["total_seconds"],
            "execution_time_formatted": execution_time["formatted_time"],
            "analysis_summary": f"Analysis failed: {e}",
            "agent_reasoning": "",
            "abnormal_event_ids": [],
            "abnormal_events": [],
            "iteration_count": state.get("iteration_count", 0)
        }
    
    return state

def _extract_final_analysis(messages):
    """Extract the final analysis from agent messages"""
    final_message = None
    for msg in reversed(messages):
        if (hasattr(msg, '__class__') and 
            msg.__class__.__name__ == 'AIMessage' and 
            hasattr(msg, 'content') and 
            msg.content and 
            (not hasattr(msg, 'tool_calls') or not msg.tool_calls)):
            final_message = msg.content
            break
    
    if not final_message:
        raise Exception("No final analysis message found")
    
    return _parse_agent_output(final_message)

def _format_analysis_result(final_analysis, execution_time, iteration_count, agent_reasoning):
    """Format the analysis result into the expected structure"""
    abnormal_events = []
    for event in final_analysis.get("abnormal_events", []):
        event_with_tools = {
            "event_id": event.get("event_id", ""),
            "event_description": event.get("event_description", ""),
            "why_abnormal": event.get("why_abnormal", ""),
            "severity": event.get("severity", ""),
            "indicators": event.get("indicators", []),
            "potential_threat": event.get("potential_threat", ""),
            "attack_category": event.get("attack_category", ""),
            "tool_enrichment": event.get("tool_enrichment", {})
        }
        abnormal_events.append(event_with_tools)
    
    return {
        "overall_assessment": final_analysis.get("overall_assessment", "UNKNOWN"),
        "total_events_analyzed": final_analysis.get("total_events_analyzed", 0),
        "execution_time_seconds": execution_time["total_seconds"],
        "execution_time_formatted": execution_time["formatted_time"],
        "analysis_summary": final_analysis.get("analysis_summary", ""),
        "agent_reasoning": agent_reasoning,
        "abnormal_event_ids": final_analysis.get("abnormal_event_ids", []),
        "abnormal_events": abnormal_events,
        "iteration_count": iteration_count
    }

def _parse_agent_output(content: str) -> dict:
    """Parse agent's final output"""
    try:
        if "```json" in content:
            json_str = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            json_str = content.split("```")[1].split("```")[0].strip()
        else:
            json_str = content.strip()
        
        return json.loads(json_str)
    except Exception as e:
        print(f"Failed to parse agent output: {e}")
        return {
            "overall_assessment": "UNKNOWN",
            "total_events_analyzed": 0,
            "analysis_summary": content[:500],
            "reasoning": "",
            "abnormal_event_ids": [],
            "abnormal_events": []
        }