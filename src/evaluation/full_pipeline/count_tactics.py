#!/usr/bin/env python3
"""
Count tactic occurrences in response analysis JSON files.

Reads all response_analysis.json files from mordor_dataset/eval_output/final_response/ directory
and counts how many times each tactic appears in the analysis.

Usage:
    python count_tactics.py [--output OUTPUT_PATH]
"""
import argparse
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any


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


# Define the 8 allowed tactics that match Mordor dataset folder names
ALLOWED_TACTICS = {
    "collection",
    "credential_access",
    "defense_evasion",
    "discovery",
    "execution",
    "lateral_movement",
    "persistance",
}


def detect_tactic_in_json(path: Path, target_tactic: str) -> int:
    """
    Detect if a tactic exists in JSON file (binary detection).
    Now simplified since tactics are standardized as lists with only the 8 allowed values.
    Returns 1 if tactic found at least once, 0 if not found.
    """

    def find_tactic_in_lists(obj):
        """Recursively search for tactic lists and check if target is present"""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "tactic" and isinstance(v, list):
                    # Check if target tactic is in the list
                    if target_tactic in v:
                        return True
                # Recurse into nested objects
                if find_tactic_in_lists(v):
                    return True
        elif isinstance(obj, list):
            for item in obj:
                if find_tactic_in_lists(item):
                    return True
        return False

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return 1 if find_tactic_in_lists(data) else 0
    except Exception as e:
        print(f"[WARNING] Error reading {path}: {e}")
        return 0


def extract_total_events_analyzed(path: Path) -> int:
    """Extract total_events_analyzed from JSON file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))

        # Check various possible locations
        if isinstance(data, dict):
            # Top level
            if "total_events_analyzed" in data:
                return data["total_events_analyzed"]

            # correlation_analysis level
            if "correlation_analysis" in data and isinstance(
                data["correlation_analysis"], dict
            ):
                if "total_events_analyzed" in data["correlation_analysis"]:
                    return data["correlation_analysis"]["total_events_analyzed"]

            # metadata level
            if "metadata" in data and isinstance(data["metadata"], dict):
                if "total_events_analyzed" in data["metadata"]:
                    return data["metadata"]["total_events_analyzed"]
                if "total_abnormal_events" in data["metadata"]:
                    return data["metadata"]["total_abnormal_events"]

        return 0
    except Exception:
        return 0


def find_response_analysis_files(base_path: Path) -> list:
    """Find all response analysis JSON files in model/tactic folder structure."""
    results = []

    # Iterate through model folders (first level)
    for model_folder in sorted(base_path.iterdir()):
        if not model_folder.is_dir():
            continue

        model_name = model_folder.name
        # Remove "models_" prefix if present
        if model_name.startswith("models_"):
            model_name = model_name[7:]  # Remove "models_" prefix

        # Iterate through tactic folders (second level)
        for tactic_folder in sorted(model_folder.iterdir()):
            if not tactic_folder.is_dir():
                continue

            tactic_label = tactic_folder.name

            # Iterate through timestamped folders (third level)
            for timestamp_folder in sorted(tactic_folder.iterdir()):
                if not timestamp_folder.is_dir():
                    continue

                # Find response analysis JSON files - handle both patterns
                json_files = []
                # Look for files ending with _response_analysis.json
                json_files.extend(timestamp_folder.glob("*_response_analysis.json"))
                # Also look for files named exactly response_analysis.json
                if (timestamp_folder / "response_analysis.json").exists():
                    json_files.append(timestamp_folder / "response_analysis.json")

                for json_file in json_files:
                    results.append(
                        {
                            "json_path": json_file,
                            "tactic_label": tactic_label,
                            "model_name": model_name,
                        }
                    )

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Count tactic occurrences in response analysis files"
    )
    parser.add_argument(
        "--output",
        default="mordor_dataset/eval_output/evaluation_results/tactic_counts_summary.json",
        help="Output file for summary results",
    )
    args = parser.parse_args()

    # Find project root and final_response directory
    current_file = Path(__file__).resolve()
    project_root = find_project_root(current_file.parent)
    final_response_dir = (
        project_root / "mordor_dataset" / "eval_output" / "final_response"
    )

    if not final_response_dir.exists():
        print(f"[ERROR] final_response directory not found at: {final_response_dir}")
        print("Run execute_pipeline.py first to generate analysis results")
        return 1

    print("=" * 80)
    print("COUNTING TACTIC OCCURRENCES")
    print("=" * 80)
    print(f"Scanning: {final_response_dir}")
    print(f"Allowed tactics: {', '.join(sorted(ALLOWED_TACTICS))}")
    print()

    # Find all response analysis files
    file_info_list = find_response_analysis_files(final_response_dir)

    if not file_info_list:
        print("[ERROR] No response analysis JSON files found")
        print(
            "Expected structure: mordor_dataset/eval_output/final_response/model_name/tactic_name/timestamp/response_analysis.json"
        )
        return 1

    print(f"Found {len(file_info_list)} response analysis files\n")

    # Process each file
    results = []
    for file_info in file_info_list:
        json_path = file_info["json_path"]
        tactic_label = file_info["tactic_label"]
        model_name = file_info["model_name"]

        # Since tactics are now standardized, we can directly use the folder name
        # The folder name should match one of the 8 allowed tactics
        target_tactic = tactic_label

        # Validate that the tactic is in our allowed list
        if target_tactic not in ALLOWED_TACTICS:
            print(
                f"[WARNING] Unknown tactic '{target_tactic}' in folder name, skipping..."
            )
            continue

        # Binary detection: 1 if detected, 0 if not
        tactic_detected = detect_tactic_in_json(json_path, target_tactic)
        total_events = extract_total_events_analyzed(json_path)

        results.append(
            {
                "file": str(json_path.relative_to(final_response_dir)),
                "model": model_name,
                "tactic": target_tactic,
                "tactic_detected": tactic_detected,
                "total_abnormal_events_detected": total_events,
            }
        )

        status = "DETECTED" if tactic_detected == 1 else "NOT DETECTED"
        print(f"  {model_name}/{tactic_label}/{json_path.parent.name}/{json_path.name}")
        print(f"    Status: {status}, Events analyzed: {total_events}")

    # Create output summary
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    summary = {
        "timestamp": datetime.now().isoformat(),
        "total_files_processed": len(results),
        "results": results,
    }

    output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # Calculate summary statistics
    total_detected = sum(1 for r in results if r["tactic_detected"] == 1)
    total_files = len(results)
    detection_rate = (total_detected / total_files * 100) if total_files > 0 else 0

    print("\n" + "=" * 80)
    print("TACTIC COUNTING COMPLETE")
    print("=" * 80)
    print(f"Processed: {total_files} files")
    print(f"Tactics detected: {total_detected}/{total_files} ({detection_rate:.1f}%)")
    print(f"Output: {output_path}")
    print("=" * 80 + "\n")

    return 0


if __name__ == "__main__":
    exit(main())
