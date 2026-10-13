"""
CTI Bench Evaluation Runner

This script provides a command-line interface to run the CTI Bench evaluation
with your Retrieval Supervisor system.
"""

import argparse
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from huggingface_hub import login as huggingface_login

# Add the project root to Python path so we can import from src
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.evaluation.cti_bench.evaluator import CTIBenchEvaluator
from src.agents.retrieval_supervisor.supervisor import RetrievalSupervisor


def setup_environment(
    dataset_dir: str = "cti_bench/datasets", output_dir: str = "cti_bench/eval_output"
):
    """Set up the environment for evaluation."""
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

    # Create necessary directories
    os.makedirs(dataset_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    # Check if datasets exist
    dataset_path = Path(dataset_dir)
    ate_file = dataset_path / "cti-ate.tsv"
    mcq_file = dataset_path / "cti-mcq.tsv"

    if not ate_file.exists() or not mcq_file.exists():
        print("ERROR: CTI Bench dataset files not found!")
        print(f"Expected files:")
        print(f"  - {ate_file}")
        print(f"  - {mcq_file}")
        print(
            "Please download the CTI Bench dataset and place the files in the correct location."
        )
        sys.exit(1)

    return True


def run_evaluation_quick_test(
    dataset_dir: str,
    output_dir: str,
    llm_model: str,
    kb_path: str,
    max_iterations: int,
    num_samples: int = 2,
    datasets: str = "all",
):
    """Run a quick test with a few samples."""
    print("Running quick test evaluation...")

    try:
        # Initialize supervisor
        supervisor = RetrievalSupervisor(
            llm_model=llm_model,
            kb_path=kb_path,
            max_iterations=max_iterations,
        )

        # Initialize evaluator
        evaluator = CTIBenchEvaluator(
            supervisor=supervisor,
            dataset_dir=dataset_dir,
            output_dir=output_dir,
        )

        # Load datasets
        ate_df, mcq_df = evaluator.load_datasets()
        ate_filtered = evaluator.filter_dataset(ate_df, "ate")
        mcq_filtered = evaluator.filter_dataset(mcq_df, "mcq")

        # Test with specified number of samples
        print(f"Testing with first {num_samples} samples of each dataset...")

        ate_sample = ate_filtered.head(num_samples)
        mcq_sample = mcq_filtered.head(num_samples)

        # Run evaluations based on dataset selection
        ate_results = None
        mcq_results = None
        ate_metrics = None
        mcq_metrics = None

        if datasets in ["ate", "all"]:
            print(f"\nEvaluating ATE dataset...")
            ate_results = evaluator.evaluate_ate_dataset(ate_sample)
            ate_metrics = evaluator.calculate_ate_metrics(ate_results)

        if datasets in ["mcq", "all"]:
            print(f"\nEvaluating MCQ dataset...")
            mcq_results = evaluator.evaluate_mcq_dataset(mcq_sample)
            mcq_metrics = evaluator.calculate_mcq_metrics(mcq_results)

        # Print results
        print("\nQuick Test Results:")
        if ate_metrics:
            print(f"ATE - Macro F1: {ate_metrics.get('macro_f1', 0.0):.3f}")
            print(f"ATE - Success Rate: {ate_metrics.get('success_rate', 0.0):.3f}")
        if mcq_metrics:
            print(f"MCQ - Accuracy: {mcq_metrics.get('accuracy', 0.0):.3f}")
            print(f"MCQ - Success Rate: {mcq_metrics.get('success_rate', 0.0):.3f}")

        return True

    except Exception as e:
        print(f"Quick test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def run_csv_metrics_calculation(
    csv_path: str,
    output_dir: str,
    model_name: str = None,
):
    """Calculate metrics from existing CSV results file."""
    print("Calculating metrics from existing CSV file...")

    try:
        # Initialize evaluator (supervisor not needed for CSV processing)
        evaluator = CTIBenchEvaluator(
            supervisor=None,  # Not needed for CSV processing
            dataset_dir="",  # Not needed for CSV processing
            output_dir=output_dir,
        )

        # Calculate metrics from CSV
        results = evaluator.calculate_metrics_from_csv(
            csv_path=csv_path,
            model_name=model_name,
        )

        print("CSV metrics calculation completed successfully!")
        return True

    except Exception as e:
        print(f"CSV metrics calculation failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def run_full_evaluation(
    dataset_dir: str,
    output_dir: str,
    llm_model: str,
    kb_path: str,
    max_iterations: int,
    datasets: str = "all",
):
    """Run the complete evaluation."""
    print("Running full evaluation...")

    try:
        # Initialize supervisor
        supervisor = RetrievalSupervisor(
            llm_model=llm_model,
            kb_path=kb_path,
            max_iterations=max_iterations,
        )

        # Initialize evaluator
        evaluator = CTIBenchEvaluator(
            supervisor=supervisor,
            dataset_dir=dataset_dir,
            output_dir=output_dir,
        )

        # Run full evaluation based on dataset selection
        if datasets == "all":
            results = evaluator.run_full_evaluation()
        elif datasets == "ate":
            results = evaluator.run_ate_evaluation()
        elif datasets == "mcq":
            results = evaluator.run_mcq_evaluation()
        else:
            print(f"Invalid dataset selection: {datasets}")
            return False

        print("Full evaluation completed successfully!")
        return True

    except Exception as e:
        print(f"Full evaluation failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_supervisor_connection(llm_model: str, kb_path: str):
    """Test the supervisor connection."""
    try:
        supervisor = RetrievalSupervisor(
            llm_model=llm_model,
            kb_path=kb_path,
            max_iterations=1,
        )
        response = supervisor.invoke_direct_query("Test query: What is T1071?")
        print("Supervisor connection successful!")
        print(f"Sample response length: {len(str(response))} characters")
        return True
    except Exception as e:
        print(f"Supervisor connection failed: {e}")
        return False


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="CTI Bench Evaluation Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run quick test with default settings
  python cti_bench_evaluation.py --mode quick

  # Run full evaluation with custom settings
  python cti_bench_evaluation.py --mode full --llm-model google_genai:gemini-2.0-flash --max-iterations 5

  # Run full evaluation on ATE dataset only
  python cti_bench_evaluation.py --mode full --datasets ate

  # Run full evaluation on MCQ dataset only
  python cti_bench_evaluation.py --mode full --datasets mcq

  # Test supervisor connection
  python cti_bench_evaluation.py --mode test

  # Run quick test with 5 samples
  python cti_bench_evaluation.py --mode quick --num-samples 5

  # Calculate metrics from existing CSV file
  python cti_bench_evaluation.py --mode csv --csv-path cti_bench/eval_output/cti-ate_gemini-2.0-flash_20251024_193022.csv

  # Calculate metrics from CSV with custom model name
  python cti_bench_evaluation.py --mode csv --csv-path results.csv --csv-model-name my-model
        """,
    )

    parser.add_argument(
        "--mode",
        choices=["quick", "full", "test", "csv"],
        required=True,
        help="Evaluation mode: 'quick' for quick test, 'full' for complete evaluation, 'test' for connection test, 'csv' for processing existing CSV files",
    )

    parser.add_argument(
        "--datasets",
        choices=["ate", "mcq", "all"],
        default="all",
        help="Which datasets to evaluate: 'ate' for CTI-ATE only, 'mcq' for CTI-MCQ only, 'all' for both (default: all)",
    )

    parser.add_argument(
        "--dataset-dir",
        default="cti_bench/datasets",
        help="Directory containing CTI Bench dataset files (default: cti_bench/datasets)",
    )

    parser.add_argument(
        "--output-dir",
        default="cti_bench/eval_output",
        help="Directory for evaluation output files (default: cti_bench/eval_output)",
    )

    parser.add_argument(
        "--llm-model",
        default="google_genai:gemini-2.0-flash",
        help="LLM model to use (default: google_genai:gemini-2.0-flash)",
    )

    parser.add_argument(
        "--kb-path",
        default="./cyber_knowledge_base",
        help="Path to knowledge base (default: ./cyber_knowledge_base)",
    )

    parser.add_argument(
        "--max-iterations",
        type=int,
        default=3,
        help="Maximum iterations for supervisor (default: 3)",
    )

    parser.add_argument(
        "--num-samples",
        type=int,
        default=2,
        help="Number of samples for quick test (default: 2)",
    )

    # CSV processing arguments
    parser.add_argument(
        "--csv-path",
        help="Path to existing CSV results file (required for csv mode)",
    )

    parser.add_argument(
        "--csv-model-name",
        help="Model name to use in summary (optional, will be extracted from filename if not provided)",
    )

    return parser.parse_args()


def main():
    """Main function."""
    args = parse_arguments()

    print("CTI Bench Evaluation Runner")
    print("=" * 50)

    # Setup environment (skip dataset validation for CSV mode)
    if args.mode != "csv":
        if not setup_environment(args.dataset_dir, args.output_dir):
            return
    else:
        # For CSV mode, just create output directory
        os.makedirs(args.output_dir, exist_ok=True)

    # Execute based on mode
    if args.mode == "quick":
        success = run_evaluation_quick_test(
            dataset_dir=args.dataset_dir,
            output_dir=args.output_dir,
            llm_model=args.llm_model,
            kb_path=args.kb_path,
            max_iterations=args.max_iterations,
            num_samples=args.num_samples,
            datasets=args.datasets,
        )
    elif args.mode == "full":
        success = run_full_evaluation(
            dataset_dir=args.dataset_dir,
            output_dir=args.output_dir,
            llm_model=args.llm_model,
            kb_path=args.kb_path,
            max_iterations=args.max_iterations,
            datasets=args.datasets,
        )
    elif args.mode == "test":
        success = test_supervisor_connection(
            llm_model=args.llm_model, kb_path=args.kb_path
        )
    elif args.mode == "csv":
        # Validate CSV mode arguments
        if not args.csv_path:
            print("ERROR: --csv-path is required for csv mode")
            sys.exit(1)

        # Check if CSV file exists
        if not os.path.exists(args.csv_path):
            print(f"ERROR: CSV file not found: {args.csv_path}")
            sys.exit(1)

        success = run_csv_metrics_calculation(
            csv_path=args.csv_path,
            output_dir=args.output_dir,
            model_name=args.csv_model_name,
        )

    if success:
        print("\nOperation completed successfully!")
    else:
        print("\nOperation failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
