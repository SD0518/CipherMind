"""
Main entry point for the Cybersecurity Log Analysis Agent
"""

import argparse
import sys
from pathlib import Path

import os
import sys
import json
from dotenv import load_dotenv
from typing import List, Dict, Any, Union, Optional
from pathlib import Path

# Add the project root to Python path so we can import from src
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.agents.log_analysis_agent.agent import LogAnalysisAgent


load_dotenv()
os.environ["GOOGLE_API_KEY"] = os.getenv("GOOGLE_API_KEY")


def main():
    """Main entry point for the cybersecurity log analysis agent"""
    parser = argparse.ArgumentParser(
        description="Agentic Cyber Log Analysis with ReAct"
    )
    parser.add_argument(
        "log_file", help="Path to log file or 'all' to process entire dataset"
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip files that have already been analyzed",
    )
    parser.add_argument(
        "--output-dir",
        default="analysis",
        help="Output directory name (default: analysis)",
    )
    args = parser.parse_args()

    # Initialize the agent
    agent = LogAnalysisAgent(
        model_name="google_genai:gemini-2.0-flash",
        temperature=0.1,
        output_dir=args.output_dir,
        max_iterations=4,
    )

    # Single file mode
    if args.log_file != "all":
        print(f"Analyzing single file: {args.log_file}")
        result = agent.analyze(args.log_file)

        # Print output location
        package_dir = Path(__file__).parent
        output_path = package_dir / args.output_dir
        print(f"\n✓ Analysis complete!")
        print(f"Results saved to: {output_path}/")
        return

    # Batch mode - find dataset directory
    package_dir = Path(__file__).parent
    project_root = package_dir.parent.parent  # Go up to project root
    dataset_dir = project_root / "mordor_dataset"

    if not dataset_dir.exists():
        print(f"Error: Dataset directory not found at {dataset_dir}")
        print("Please ensure 'mordor_dataset' exists at project root level")
        sys.exit(1)

    results = agent.analyze_batch(
        dataset_dir=str(dataset_dir), skip_existing=args.skip_existing
    )

    # Print output location
    output_path = package_dir / args.output_dir
    print(f"\n✓ Batch analysis complete!")
    print(f"Results saved to: {output_path}/")


if __name__ == "__main__":
    main()
