import os
import json
import time
from datetime import datetime

from state_models import AnalysisState

def load_logs(state: AnalysisState):
    """Load logs from file and initialize state"""
    filename = os.path.basename(state["log_file"])
    print(f"Loading logs from: {filename}")
    
    # Record start time
    state["start_time"] = time.time()
    
    try:
        with open(state["log_file"], "r", encoding="utf-8") as f:
            raw = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        raise
    
    state["raw_logs"] = raw
    state["messages"] = []
    state["agent_reasoning"] = ""
    state["agent_observations"] = []
    state["iteration_count"] = 0
    state["critic_feedback"] = ""
    state["iteration_history"] = []
    state["end_time"] = 0.0
    
    return state

def preprocess_logs(state: AnalysisState):
    """Preprocess logs for analysis - sample large files"""
    raw = state["raw_logs"]
    line_count = raw.count("\n")
    print(f"Loaded {line_count} lines, {len(raw)} characters")
    
    if len(raw) > 20000:
        first = raw[:7000]
        middle = raw[len(raw)//2 - 3000 : len(raw)//2 + 3000]
        last = raw[-7000:]
        sampled = f"{first}\n...[MIDDLE]...\n{middle}\n...[END]...\n{last}"
        state["prepared_logs"] = f"TOTAL LINES: {line_count}\nSAMPLED:\n{sampled}"
        print("Large file detected - using sampling strategy")
    else:
        state["prepared_logs"] = f"TOTAL LINES: {line_count}\n\n{raw}"
    
    return state

def save_results(state: AnalysisState):
    """Save analysis results and messages to files"""
    input_name = os.path.splitext(os.path.basename(state["log_file"]))[0]
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    analysis_dir = os.path.join(project_root, "analysis", input_name)

    os.makedirs(analysis_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(analysis_dir, f"{input_name}_analysis_{ts}.json")

    try:
        # Save main analysis result
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(state["analysis_result"], f, indent=2)
        
        # Save iteration history
        history_file = os.path.join(analysis_dir, f"{input_name}_iterations_{ts}.json")
        with open(history_file, "w", encoding="utf-8") as f:
            json.dump(state.get("iteration_history", []), f, indent=2)
        
        # Save messages history
        messages_file = os.path.join(analysis_dir, f"{input_name}_messages_{ts}.json")
        serializable_messages = []
        for msg in state.get("messages", []):
            if isinstance(msg, dict):
                serializable_messages.append(msg)
            else:
                msg_dict = {
                    "type": msg.__class__.__name__,
                    "content": msg.content if hasattr(msg, 'content') else str(msg)
                }
                if hasattr(msg, 'tool_calls') and msg.tool_calls:
                    msg_dict["tool_calls"] = [
                        {
                            "name": tc.get("name", ""),
                            "args": tc.get("args", {})
                        } for tc in msg.tool_calls
                    ]
                serializable_messages.append(msg_dict)
        
        with open(messages_file, "w", encoding="utf-8") as f:
            json.dump(serializable_messages, f, indent=2)
        
    except Exception as e:
        print(f"Error saving results: {e}")

    return state

def display_results(state: AnalysisState):
    """Display formatted analysis results"""
    result = state["analysis_result"]
    assessment = result.get("overall_assessment", "UNKNOWN")
    execution_time = result.get("execution_time_formatted", "Unknown")
    abnormal_events = result.get("abnormal_events", [])
    iteration_count = result.get("iteration_count", 1)
    
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print("="*60)
    
    print(f"ASSESSMENT: {assessment}")
    print(f"ITERATIONS: {iteration_count}")
    print(f"EXECUTION TIME: {execution_time}")
    print(f"EVENTS ANALYZED: {result.get('total_events_analyzed', 'Unknown')}")
    
    # Tools Used
    tools_used = set()
    for msg in state.get("messages", []):
        if hasattr(msg, 'tool_calls') and msg.tool_calls:
            for tc in msg.tool_calls:
                tool_name = tc.get("name", "")
                if tool_name:
                    tools_used.add(tool_name)
    
    if tools_used:
        print(f"TOOLS USED: {len(tools_used)} tools")
        print(f"  Types: {', '.join(sorted(tools_used))}")
    else:
        print("TOOLS USED: None")
    
    # Abnormal Events
    if abnormal_events:
        print(f"\nABNORMAL EVENTS: {len(abnormal_events)}")
        for event in abnormal_events:
            severity = event.get('severity', 'UNKNOWN')
            event_id = event.get('event_id', 'N/A')
            print(f"  EventID {event_id} [{severity}]")
    else:
        print("\nNO ABNORMAL EVENTS")
    
    print("="*60)
    
    return state