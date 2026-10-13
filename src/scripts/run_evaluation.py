#!/usr/bin/env python3
"""
Run Evaluation Pipeline

This orchestrates the evaluation workflow on existing final_response data:
1. Count tactic occurrences (count_tactics.py)
2. Generate evaluation metrics (evaluate_metrics.py)
3. Compare models (compare_models.py)
4. Generate CSV with simple metrics (generate_metrics_csv.py)

NOTE: This does NOT run the full 3-agent pipeline.
      Use execute_pipeline.py separately to generate final_response data first.

Usage:
    python run_evaluation.py [--skip-counting]
"""
import subprocess
import sys
from pathlib import Path
from datetime import datetime
import argparse


def find_project_root(start: Path) -> Path:
    """Find the project root by looking for common markers."""
    for p in [start] + list(start.parents):
        if (
            (p / "final_response").exists()
            or (p / "src").exists()
            or (p / ".git").exists()
        ):
            return p
    return start.parent


class EvaluationRunner:
    """Orchestrates the evaluation workflow"""

    def __init__(self, skip_counting: bool = False):
        self.skip_counting = skip_counting
        current_file = Path(__file__).resolve()
        self.project_root = find_project_root(current_file.parent)
        # Point to the evaluation/full_pipeline directory for scripts
        self.eval_dir = self.project_root / "src" / "evaluation" / "full_pipeline"
        # Output directory now in mordor_dataset/eval_output
        self.output_dir = (
            self.project_root / "mordor_dataset" / "eval_output" / "evaluation_results"
        )
        self.start_time = None

    def print_header(self, step: str, description: str):
        """Print a formatted step header"""
        print("\n" + "=" * 80)
        print(f"STEP {step}: {description}")
        print("=" * 80)

    def run_command(self, description: str, cmd: list) -> bool:
        """Run a command and handle errors"""
        print(f"\n{description}")
        print(f"Command: {' '.join(str(c) for c in cmd)}\n")

        try:
            result = subprocess.run(cmd, check=True)
            print(f"\n[SUCCESS] {description} completed")
            return True
        except subprocess.CalledProcessError as e:
            print(f"\n[ERROR] {description} failed with exit code {e.returncode}")
            return False
        except Exception as e:
            print(f"\n[ERROR] Unexpected error during {description}: {e}")
            return False

    def step_1_count_tactics(self) -> bool:
        """Step 1: Count tactic occurrences"""
        self.print_header("1/3", "Counting Tactic Occurrences")

        if self.skip_counting:
            print("Skipping tactic counting (--skip-counting flag set)")
            print("Using existing tactic_counts_summary.json")
            return True

        final_response_dir = (
            self.project_root / "mordor_dataset" / "eval_output" / "final_response"
        )
        # Ensure output directory exists
        self.output_dir.mkdir(exist_ok=True)
        output_file = self.output_dir / "tactic_counts_summary.json"

        if not final_response_dir.exists():
            print(
                f"[ERROR] final_response directory not found at: {final_response_dir}"
            )
            print(
                "Run execute_pipeline_all_datasets.py first to generate analysis results"
            )
            return False

        # Count response_analysis.json files
        analysis_files = list(final_response_dir.rglob("response_analysis.json"))
        if not analysis_files:
            print(f"[ERROR] No response_analysis.json files found in final_response")
            print(
                "Run execute_pipeline_all_datasets.py first to generate analysis results"
            )
            return False

        print(f"Found {len(analysis_files)} analysis files")
        print(f"Output: {output_file}")

        script_path = self.eval_dir / "count_tactics.py"
        return self.run_command(
            "Count tactic occurrences",
            [sys.executable, str(script_path), "--output", str(output_file)],
        )

    def step_2_evaluate_metrics(self) -> bool:
        """Step 2: Generate evaluation metrics for each model"""
        self.print_header("2/3", "Generating Evaluation Metrics")

        tactic_counts_file = self.output_dir / "tactic_counts_summary.json"
        output_file = self.output_dir / "evaluation_report.json"

        if not tactic_counts_file.exists():
            print(f"[ERROR] Tactic counts file not found: {tactic_counts_file}")
            print("Run step 1 first or remove --skip-counting flag")
            return False

        print(f"Input: {tactic_counts_file}")
        print(f"Output: {output_file}")
        print(
            "Note: Individual model reports will be saved as evaluation_report_[model_name].json"
        )

        script_path = self.eval_dir / "evaluate_metrics.py"
        return self.run_command(
            "Generate evaluation metrics for each model",
            [
                sys.executable,
                str(script_path),
                "--input",
                str(tactic_counts_file),
                "--output",
                str(output_file),
            ],
        )

    def step_3_compare_models(self) -> bool:
        """Step 3: Compare models"""
        self.print_header("3/4", "Comparing Models")

        tactic_counts_file = self.output_dir / "tactic_counts_summary.json"
        output_file = self.output_dir / "model_comparison.json"

        if not tactic_counts_file.exists():
            print(f"[ERROR] Tactic counts file not found: {tactic_counts_file}")
            print("Run step 1 first or remove --skip-counting flag")
            return False

        print(f"Input: {tactic_counts_file}")
        print(f"Output: {output_file}")

        script_path = self.eval_dir / "compare_models.py"
        return self.run_command(
            "Compare models",
            [
                sys.executable,
                str(script_path),
                "--input",
                str(tactic_counts_file),
                "--output",
                str(output_file),
            ],
        )

    def step_4_generate_csv(self) -> bool:
        """Step 4: Generate CSV with simple metrics"""
        self.print_header("4/4", "Generating CSV Metrics")

        tactic_counts_file = self.output_dir / "tactic_counts_summary.json"
        output_file = self.output_dir / "model_metrics.csv"

        if not tactic_counts_file.exists():
            print(f"[ERROR] Tactic counts file not found: {tactic_counts_file}")
            print("Run step 1 first or remove --skip-counting flag")
            return False

        print(f"Input: {tactic_counts_file}")
        print(f"Output: {output_file}")

        script_path = self.eval_dir / "generate_metrics_csv.py"
        return self.run_command(
            "Generate CSV with simple metrics (F1, accuracy, precision, recall)",
            [
                sys.executable,
                str(script_path),
                "--input",
                str(tactic_counts_file),
                "--output",
                str(output_file),
            ],
        )

    def run(self) -> int:
        """Run the evaluation pipeline"""
        self.start_time = datetime.now()

        print("\n" + "=" * 80)
        print("EVALUATION PIPELINE")
        print("=" * 80)
        print(f"Project Root: {self.project_root}")
        print(f"Evaluation Dir: {self.eval_dir}")
        print(f"Output Dir: {self.output_dir}")
        print(f"Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")

        # Step 1: Count tactics
        if not self.step_1_count_tactics():
            print("\n[ERROR] Evaluation failed at Step 1")
            return 1

        # Step 2: Evaluate metrics
        if not self.step_2_evaluate_metrics():
            print("\n[ERROR] Evaluation failed at Step 2")
            return 1

        # Step 3: Compare models
        if not self.step_3_compare_models():
            print("\n[ERROR] Evaluation failed at Step 3")
            return 1

        # Step 4: Generate CSV metrics
        if not self.step_4_generate_csv():
            print("\n[ERROR] Evaluation failed at Step 4")
            return 1

        # Success summary
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        print("\n" + "=" * 80)
        print("EVALUATION PIPELINE COMPLETED SUCCESSFULLY")
        print("=" * 80)
        print(f"Duration: {duration:.1f} seconds")
        print(f"\nOutput Files:")
        print(f"  - {self.output_dir / 'tactic_counts_summary.json'}")
        print(f"  - {self.output_dir / 'evaluation_report.json'} (summary)")
        print(
            f"  - {self.output_dir / 'evaluation_report_[model_name].json'} (per model)"
        )
        print(f"  - {self.output_dir / 'model_comparison.json'}")
        print(
            f"  - {self.output_dir / 'model_metrics.csv'} (simple metrics: F1, accuracy, precision, recall)"
        )
        print(f"\nAll outputs are now organized under: mordor_dataset/eval_output/")
        print("=" * 80 + "\n")

        return 0


def main():
    parser = argparse.ArgumentParser(
        description="Run evaluation pipeline on existing final_response data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full evaluation (count tactics + evaluate metrics + compare models)
  python run_evaluation.py
  
  # Skip counting, only evaluate (use existing tactic_counts_summary.json)
  python run_evaluation.py --skip-counting

Note: This does NOT run the 3-agent pipeline.
      Use execute_pipeline_all_datasets.py separately to process mordor dataset files.
        """,
    )
    parser.add_argument(
        "--skip-counting",
        action="store_true",
        help="Skip counting tactics, use existing tactic_counts_summary.json",
    )

    args = parser.parse_args()

    runner = EvaluationRunner(skip_counting=args.skip_counting)
    exit_code = runner.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
