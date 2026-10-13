#!/usr/bin/env python3
"""
Run script for the simple integrated pipeline

Usage examples:
    python run_simple.py sample_log.json
    python run_simple.py /path/to/mordor_dataset/credential_access_log.json
    python run_simple.py sample_log.json "Focus on lateral movement techniques"
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from huggingface_hub import login as huggingface_login

# Add paths for imports
# We're in src/scripts/, so go up to project root
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Import the simple pipeline from src/full_pipeline/
try:
    from src.full_pipeline.simple_pipeline import analyze_log_file
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure simple_pipeline.py is in src/full_pipeline/ directory")
    print(f"Current working directory: {os.getcwd()}")
    print(f"Script location: {Path(__file__).parent}")
    sys.exit(1)


def setup_environment(model_name: str = "google_genai:gemini-2.0-flash"):
    """
    Setup environment variables and check requirements.

    Args:
        model_name: Name of the model to validate environment for
    """
    load_dotenv()
    # Load environment variables
    if os.getenv("GOOGLE_API_KEY"):
        os.environ["GOOGLE_API_KEY"] = os.getenv("GOOGLE_API_KEY")

    if os.getenv("GROQ_API_KEY"):
        os.environ["GROQ_API_KEY"] = os.getenv("GROQ_API_KEY")

    if os.getenv("OPENAI_API_KEY"):
        os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

    if os.getenv("HF_TOKEN"):
        huggingface_login(token=os.getenv("HF_TOKEN"))

    # Determine required environment variable based on model name
    if "google_genai" in model_name or "gemini" in model_name:
        required_env_var = "GOOGLE_API_KEY"
    elif "groq" in model_name or "gpt-oss" in model_name or "llama" in model_name:
        required_env_var = "GROQ_API_KEY"
    elif "openai" in model_name or "gpt-" in model_name:
        required_env_var = "OPENAI_API_KEY"
    else:
        print(
            f"[WARNING] Unknown model '{model_name}', using default environment checks"
        )
        required_env_var = "GOOGLE_API_KEY"

    if not os.getenv(required_env_var):
        print(f"Error: {required_env_var} not found in environment variables")
        print(f"Required for model: {model_name}")
        print(f"Please set it in your .env file or environment.")
        print("\nAvailable models and their requirements:")
        print("  âœ“ google_genai:gemini-2.0-flash: requires GOOGLE_API_KEY")
        print("  âœ“ google_genai:gemini-1.5-flash: requires GOOGLE_API_KEY")
        print("  âœ“ groq:gpt-oss-120b: requires GROQ_API_KEY")
        print("  âœ“ groq:gpt-oss-20b: requires GROQ_API_KEY")
        print("  âœ“ groq:llama-3.1-8b-instant: requires GROQ_API_KEY")
        print("  âœ“ groq:llama-3.3-70b-versatile: requires GROQ_API_KEY")
        sys.exit(1)

    print(f"Environment setup complete. Using {required_env_var} for {model_name}")


def validate_inputs(log_file: str):
    """Validate input parameters."""
    if not os.path.exists(log_file):
        print(f"Error: Log file not found: {log_file}")

        # Suggest common locations - check from project root
        os.chdir(project_root)
        suggestions = []
        if Path("mordor_dataset").exists():
            suggestions.append("./mordor_dataset/")
        if Path("../mordor_dataset").exists():
            suggestions.append("../mordor_dataset/")

        if suggestions:
            print("Try looking in these directories:")
            for suggestion in suggestions:
                json_files = list(Path(suggestion).glob("*.json"))
                if json_files:
                    print(f"  {suggestion}")
                    for f in json_files[:3]:  # Show first 3 files
                        print(f"    - {f.name}")
                    if len(json_files) > 3:
                        print(f"    ... and {len(json_files) - 3} more files")

        sys.exit(1)

    # Check if it's a JSON file
    if not log_file.endswith(".json"):
        print(f"Warning: File doesn't have .json extension: {log_file}")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != "y":
            sys.exit(1)


def main():
    """Main entry point."""
    # Check arguments
    if len(sys.argv) < 2:
        print("Cybersecurity Log Analysis Pipeline")
        print("=" * 50)
        print("Usage: python run_simple_pipeline.py <log_file> [options]")
        print("")
        print("Arguments:")
        print("  log_file              Path to the log file to analyze")
        print("")
        print("Options:")
        print('  --query "TEXT"        Optional query for additional context')
        print(
            "  --model MODEL_NAME    Model to use for analysis (default: google_genai:gemini-2.0-flash)"
        )
        print("  --temp TEMPERATURE    Temperature for model generation (default: 0.1)")
        print(
            "  --output-dir DIR      Output directory for results (default: mordor_dataset/eval_output)"
        )
        print("")
        print("Examples:")
        print("  python run_simple_pipeline.py sample_log.json")
        print(
            "  python run_simple_pipeline.py mordor_dataset/datasets/credential_access.json"
        )
        print(
            "  python run_simple_pipeline.py sample.json --query 'Focus on privilege escalation'"
        )
        print("  python run_simple_pipeline.py sample.json --model gpt-oss-120b")
        print(
            "  python run_simple_pipeline.py sample.json --model llama-3.1-8b-instant --temp 0.2"
        )
        print("  python run_simple_pipeline.py sample.json --output-dir custom_output")
        print("")
        print("Available models:")
        print("  - google_genai:gemini-2.0-flash")
        print("  - google_genai:gemini-1.5-flash")
        print("  - groq:gpt-oss-120b")
        print("  - groq:gpt-oss-20b")
        print("  - groq:llama-3.1-8b-instant")
        print("  - groq:llama-3.3-70b-versatile")
        print("")

        # Try to find sample files from project root
        os.chdir(project_root)
        sample_files = []
        for pattern in ["*.json", "mordor_dataset/*.json", "../mordor_dataset/*.json"]:
            sample_files.extend(Path(".").glob(pattern))

        if sample_files:
            print("Available log files found:")
            for f in sample_files[:5]:
                print(f"  {f}")
            if len(sample_files) > 5:
                print(f"  ... and {len(sample_files) - 5} more files")

        sys.exit(1)

    # Parse arguments
    log_file = sys.argv[1]
    query = None
    model_name = "google_genai:gemini-2.0-flash"
    temperature = 0.1
    output_dir = "mordor_dataset/eval_output"

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--query" and i + 1 < len(sys.argv):
            query = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--model" and i + 1 < len(sys.argv):
            model_name = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--temp" and i + 1 < len(sys.argv):
            try:
                temperature = float(sys.argv[i + 1])
            except ValueError:
                print(f"Error: Invalid temperature value: {sys.argv[i + 1]}")
                sys.exit(1)
            i += 2
        elif sys.argv[i] == "--output-dir" and i + 1 < len(sys.argv):
            output_dir = sys.argv[i + 1]
            i += 2
        else:
            # Backward compatibility: treat as query if no flag
            if not query:
                query = sys.argv[i]
            i += 1

    print("Cybersecurity Multi-Agent Pipeline")
    print("=" * 50)
    print(f"Log file: {log_file}")
    print(f"Model: {model_name}")
    print(f"Temperature: {temperature}")
    print(f"Output directory: {output_dir}")
    print(f"User query: {query or 'None'}")
    print("")

    # Setup and validation
    setup_environment(model_name)
    validate_inputs(log_file)

    # Run the pipeline
    try:
        print("Initializing pipeline...")
        # Extract tactic from file path if it's in a subdirectory
        tactic = None
        log_path = Path(log_file)
        if log_path.parent.name != "mordor_dataset":
            tactic = log_path.parent.name

        # Create subdirectories within the output directory
        analysis_dir = os.path.join(output_dir, "analysis")
        final_response_dir = os.path.join(output_dir, "final_response")

        # Ensure output directories exist
        os.makedirs(analysis_dir, exist_ok=True)
        os.makedirs(final_response_dir, exist_ok=True)

        final_state = analyze_log_file(
            log_file,
            query,
            tactic,
            model_name=model_name,
            temperature=temperature,
            log_agent_output_dir=analysis_dir,
            response_agent_output_dir=final_response_dir,
        )
        print(final_state["markdown_report"])
        print("\nPipeline execution completed successfully!")

    except KeyboardInterrupt:
        print("\nPipeline interrupted by user.")
        sys.exit(0)

    except Exception as e:
        print(f"\nPipeline failed with error: {e}")

        # Provide helpful debugging info
        print("\nDebugging information:")
        print(f"  - Working directory: {os.getcwd()}")
        print(f"  - Log file exists: {os.path.exists(log_file)}")
        print(f"  - Python path: {sys.path[0]}")

        # Check for common issues
        if "knowledge base" in str(e).lower():
            print("\nPossible solution:")
            print(
                "  Make sure ./cyber_knowledge_base directory exists and is properly initialized"
            )
        elif "import" in str(e).lower():
            print("\nPossible solution:")
            print(
                "  Make sure you're running from the correct directory with access to src/"
            )

        sys.exit(1)


if __name__ == "__main__":
    main()