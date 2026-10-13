#!/usr/bin/env python3
"""
Execute the complete 3-agent pipeline on all JSON files in mordor_dataset.

This runs:
1. Log Analysis Agent
2. Retrieval Supervisor (with Database Agent and Grader)
3. Response Agent

Outputs are saved to final_response/ folder.

Usage: python execute_pipeline.py [--model MODEL_NAME]
"""
import subprocess
from pathlib import Path
import sys
import argparse


def find_project_root(start: Path) -> Path:
    """Find the project root by looking for common markers."""
    for p in [start] + list(start.parents):
        if (
            (p / "mordor_dataset").exists()
            or (p / "src").exists()
            or (p / ".git").exists()
        ):
            return p
    return start.parent


def main():
    """Execute pipeline on all mordor dataset files"""
    parser = argparse.ArgumentParser(
        description="Execute pipeline on all mordor dataset files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with default model (Gemini 2.0 Flash)
  python execute_pipeline.py
  
  # Run with specific model
  python execute_pipeline.py --model google_genai:gemini-2.0-flash
  python execute_pipeline.py --model groq:gpt-oss-120b
  python execute_pipeline.py --model groq:llama-3.1-8b-instant

Available models:
  - google_genai:gemini-2.0-flash (default)
  - google_genai:gemini-1.5-flash
  - groq:gpt-oss-120b
  - groq:gpt-oss-20b
  - groq:llama-3.1-8b-instant
  - groq:llama-3.3-70b-versatile
        """,
    )
    parser.add_argument(
        "--model",
        default="google_genai:gemini-2.0-flash",
        help="Model to use for analysis (default: google_genai:gemini-2.0-flash)",
    )

    args = parser.parse_args()
    model_name = args.model

    current_file = Path(__file__).resolve()
    project_root = find_project_root(current_file.parent)
    mordor_dir = project_root / "mordor_dataset"
    datasets_dir = mordor_dir / "datasets"

    if not datasets_dir.exists():
        print(f"[ERROR] mordor_dataset/datasets not found at {datasets_dir}")
        sys.exit(1)

    # Find all JSON files in the datasets directory
    files = sorted([p for p in datasets_dir.rglob("*.json")])
    if not files:
        print("[ERROR] No JSON files found in mordor_dataset/datasets")
        sys.exit(1)

    print("=" * 80)
    print("EXECUTING FULL PIPELINE ON ALL MORDOR FILES")
    print("=" * 80)
    print(f"Model: {model_name}")
    print(f"Found {len(files)} files to process\n")

    # Group files by folder
    files_by_folder = {}
    for f in files:
        folder_name = f.parent.name
        if folder_name not in files_by_folder:
            files_by_folder[folder_name] = []
        files_by_folder[folder_name].append(f)

    # Process files
    total_success = 0
    total_failed = 0

    for folder_name in sorted(files_by_folder.keys()):
        folder_files = files_by_folder[folder_name]
        print(f"\n{'='*80}")
        print(f"Processing folder: {folder_name} ({len(folder_files)} files)")
        print(f"{'='*80}")

        for f in folder_files:
            # Assume pipeline script is at src/scripts/run_simple_pipeline.py
            pipeline_script = (
                project_root / "src" / "scripts" / "run_simple_pipeline.py"
            )

            if not pipeline_script.exists():
                print(f"[ERROR] Pipeline script not found: {pipeline_script}")
                sys.exit(1)

            # Set output directory to mordor_dataset/eval_output
            output_dir = str(mordor_dir / "eval_output")
            cmd = [
                sys.executable,
                str(pipeline_script),
                str(f),
                "--model",
                model_name,
                "--output-dir",
                output_dir,
            ]
            print(f"\n--- Processing: {f.relative_to(datasets_dir)}")
            print(f"    Model: {model_name}")
            print(f"    Output: {output_dir}")

            try:
                subprocess.run(cmd, check=True)
                total_success += 1
            except subprocess.CalledProcessError as e:
                print(f"[ERROR] Pipeline failed for {f.name}: {e}")
                total_failed += 1

    # Summary
    print("\n" + "=" * 80)
    print("PIPELINE EXECUTION COMPLETE")
    print("=" * 80)
    print(f"Model used: {model_name}")
    print(f"Total files processed: {len(files)}")
    print(f"Successful: {total_success}")
    print(f"Failed: {total_failed}")
    print(f"Results saved to: {mordor_dir / 'eval_output'}/")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()