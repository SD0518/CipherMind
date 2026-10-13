# main.py
import argparse
import os
import glob
from datetime import datetime
from langgraph.graph import StateGraph, END
from state_models import AnalysisState
from workflow_nodes import load_logs, preprocess_logs, save_results, display_results
from react_engine import react_agent_analysis

def create_workflow():
    """Create and configure the analysis workflow graph"""
    workflow = StateGraph(AnalysisState)
    
    # Add nodes
    workflow.add_node("load_logs", load_logs)
    workflow.add_node("preprocess_logs", preprocess_logs)
    workflow.add_node("react_agent_analysis", react_agent_analysis)
    workflow.add_node("save_results", save_results)
    workflow.add_node("display_results", display_results)

    # Define workflow edges
    workflow.set_entry_point("load_logs")
    workflow.add_edge("load_logs", "preprocess_logs")
    workflow.add_edge("preprocess_logs", "react_agent_analysis")
    workflow.add_edge("react_agent_analysis", "save_results")
    workflow.add_edge("save_results", "display_results")
    workflow.add_edge("display_results", END)

    return workflow.compile()

def initialize_state(log_file: str) -> dict:
    """Initialize the analysis state with default values"""
    return {
        "log_file": log_file,
        "raw_logs": "",
        "prepared_logs": "",
        "analysis_result": {},
        "messages": [],
        "agent_reasoning": "",
        "agent_observations": [],
        "iteration_count": 0,
        "critic_feedback": "",
        "iteration_history": [],
        "start_time": 0.0,
        "end_time": 0.0
    }

def get_output_path(log_file: str) -> str:
    """Get the output file path for a given log file"""
    input_name = os.path.splitext(os.path.basename(log_file))[0]
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    analysis_dir = os.path.join(project_root, "analysis", input_name)
    
    if os.path.exists(analysis_dir):
        existing_files = glob.glob(os.path.join(analysis_dir, f"{input_name}_analysis_*.json"))
        if existing_files:
            return existing_files[0]
    return None

def analyze_single_file(log_file: str, app, skip_existing: bool = False) -> dict:
    """Analyze a single log file"""
    try:
        if skip_existing:
            existing = get_output_path(log_file)
            if existing:
                return {
                    "success": True,
                    "log_file": log_file,
                    "message": "Skipped (already analyzed)",
                    "result": None
                }
        
        state = initialize_state(log_file)
        app.invoke(state)
        
        return {
            "success": True,
            "log_file": log_file,
            "message": "Analysis completed",
            "result": state.get("analysis_result")
        }
        
    except Exception as e:
        return {
            "success": False,
            "log_file": log_file,
            "message": f"Error: {str(e)}",
            "result": None
        }

def find_dataset_files(dataset_dir: str) -> list:
    """Find all JSON files in the dataset directory"""
    if not os.path.exists(dataset_dir):
        print(f"Error: Dataset directory not found: {dataset_dir}")
        return []
    
    json_files = glob.glob(os.path.join(dataset_dir, "*.json"))
    return sorted(json_files)

def print_batch_summary(results: list, start_time: datetime, end_time: datetime):
    """Print summary of batch processing results"""
    total = len(results)
    successful = sum(1 for r in results if r["success"])
    skipped = sum(1 for r in results if "Skipped" in r["message"])
    failed = total - successful
    
    duration = (end_time - start_time).total_seconds()
    
    print("\n" + "="*60)
    print("BATCH ANALYSIS SUMMARY")
    print("="*60)
    print(f"Total files: {total}")
    print(f"Successful: {successful}")
    print(f"Skipped: {skipped}")
    print(f"Failed: {failed}")
    print(f"Total time: {duration:.2f} seconds ({duration/60:.2f} minutes)")
    
    if failed > 0:
        print(f"\nFailed files:")
        for r in results:
            if not r["success"]:
                filename = os.path.basename(r["log_file"])
                print(f"  - {filename}: {r['message']}")
    
    print("="*60 + "\n")

def main():
    """Main entry point for the cybersecurity log analysis agent"""
    parser = argparse.ArgumentParser(description="Agentic Cyber Log Analysis with ReAct")
    parser.add_argument("log_file", help="Path to log file or 'all' to process entire dataset")
    parser.add_argument("--skip-existing", action="store_true", 
                       help="Skip files that have already been analyzed")
    args = parser.parse_args()

    app = create_workflow()

    if args.log_file != "all":
        state = initialize_state(args.log_file)
        app.invoke(state)
        return

    # Batch mode
    print("="*60)
    print("BATCH MODE: Analyzing all files in dataset")
    print("="*60 + "\n")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_dir = os.path.join(script_dir, "..", "mordor_dataset")
    dataset_dir = os.path.normpath(dataset_dir)
    
    files = find_dataset_files(dataset_dir)
    
    if not files:
        print("No JSON files found in dataset directory")
        return
    
    print(f"Found {len(files)} files to analyze")
    if args.skip_existing:
        print("Skip mode enabled: Already analyzed files will be skipped")
    print()
    
    results = []
    batch_start = datetime.now()
    
    for idx, file_path in enumerate(files, 1):
        filename = os.path.basename(file_path)
        print(f"\n[{idx}/{len(files)}] Processing: {filename}")
        print("-" * 60)
        
        result = analyze_single_file(file_path, app, args.skip_existing)
        results.append(result)
        
        if result["success"]:
            print(f"Status: {result['message']}")
        else:
            print(f"Status: FAILED - {result['message']}")
    
    batch_end = datetime.now()
    print_batch_summary(results, batch_start, batch_end)

if __name__ == "__main__":
    main()