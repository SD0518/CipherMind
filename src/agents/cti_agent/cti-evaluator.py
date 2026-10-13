import re
import json
import os
from typing import List, Set, Dict, Tuple
from pathlib import Path
import pandas as pd
from dotenv import load_dotenv

# Import your CTI tools
from langchain.chat_models import init_chat_model
from langchain_tavily import TavilySearch
import sys

sys.path.append("src/agents/cti_agent")
from cti_tools import CTITools
from config import MODEL_NAME, CTI_SEARCH_CONFIG


class CTIToolsEvaluator:
    """Evaluator for CTI tools on CTIBench benchmarks."""

    def __init__(self):
        """Initialize the evaluator with CTI tools."""
        load_dotenv()

        # Initialize LLM
        self.llm = init_chat_model(MODEL_NAME, temperature=0.1)

        # Initialize search (needed for CTITools init, even if not used in evaluation)
        search_config = {**CTI_SEARCH_CONFIG, "api_key": os.getenv("TAVILY_API_KEY")}
        self.cti_search = TavilySearch(**search_config)

        # Initialize CTI Tools
        self.cti_tools = CTITools(self.llm, self.cti_search)

        # Storage for results
        self.ate_results = []
        self.taa_results = []

    # ==================== CTI-ATE: MITRE Technique Extraction Tool ====================

    def extract_technique_ids(self, text: str) -> Set[str]:
        """
        Extract MITRE technique IDs from text.
        Looks for patterns like T1234 (main techniques only, no subtechniques).

        Args:
            text: Text containing technique IDs

        Returns:
            Set of technique IDs (e.g., {'T1071', 'T1059'})
        """
        # Pattern for main techniques only (T#### not T####.###)
        pattern = r"\bT\d{4}\b"
        matches = re.findall(pattern, text)
        return set(matches)

    def calculate_ate_metrics(
        self, predicted: Set[str], ground_truth: Set[str]
    ) -> Dict[str, float]:
        """
        Calculate precision, recall, and F1 score for technique extraction.

        Args:
            predicted: Set of predicted technique IDs
            ground_truth: Set of ground truth technique IDs

        Returns:
            Dictionary with precision, recall, f1, tp, fp, fn
        """
        tp = len(predicted & ground_truth)  # True positives
        fp = len(predicted - ground_truth)  # False positives
        fn = len(ground_truth - predicted)  # False negatives

        precision = tp / len(predicted) if len(predicted) > 0 else 0.0
        recall = tp / len(ground_truth) if len(ground_truth) > 0 else 0.0
        f1 = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "predicted_count": len(predicted),
            "ground_truth_count": len(ground_truth),
        }

    def evaluate_mitre_extraction_tool(
        self,
        sample_id: str,
        description: str,
        ground_truth: str,
        platform: str = "Enterprise",
    ) -> Dict:
        """
        Evaluate extract_mitre_techniques tool on a single sample.

        Args:
            sample_id: Sample identifier (e.g., URL)
            description: Malware/report description to analyze
            ground_truth: Ground truth technique IDs (comma-separated)
            platform: MITRE platform (Enterprise, Mobile, ICS)

        Returns:
            Dictionary with evaluation metrics
        """
        print(f"Evaluating {sample_id[:60]}...")

        # Call the extract_mitre_techniques tool
        tool_output = self.cti_tools.extract_mitre_techniques(description, platform)

        # Extract technique IDs from tool output
        predicted_ids = self.extract_technique_ids(tool_output)
        gt_ids = set([t.strip() for t in ground_truth.split(",") if t.strip()])

        # Calculate metrics
        metrics = self.calculate_ate_metrics(predicted_ids, gt_ids)

        result = {
            "sample_id": sample_id,
            "platform": platform,
            "description": description[:100] + "...",
            "tool_output": tool_output[:500] + "...",  # Truncate for storage
            "predicted": sorted(predicted_ids),
            "ground_truth": sorted(gt_ids),
            "missing": sorted(gt_ids - predicted_ids),  # False negatives
            "extra": sorted(predicted_ids - gt_ids),  # False positives
            **metrics,
        }

        self.ate_results.append(result)
        return result

    def evaluate_ate_from_tsv(
        self, filepath: str = "cti-bench/data/cti-ate.tsv", limit: int = None
    ) -> pd.DataFrame:
        """
        Evaluate extract_mitre_techniques tool on CTI-ATE benchmark.

        Args:
            filepath: Path to CTI-ATE TSV file
            limit: Optional limit on number of samples to evaluate

        Returns:
            DataFrame with results for each sample
        """
        print(f"\n{'='*80}")
        print(f"Evaluating extract_mitre_techniques tool on CTI-ATE benchmark")
        print(f"{'='*80}\n")

        # Load benchmark
        df = pd.read_csv(filepath, sep="\t")

        if limit:
            df = df.head(limit)

        print(f"Loaded {len(df)} samples from {filepath}")
        print(f"Starting evaluation...\n")

        # Evaluate each sample
        for idx, row in df.iterrows():
            try:
                self.evaluate_mitre_extraction_tool(
                    sample_id=row["URL"],
                    description=row["Description"],
                    ground_truth=row["GT"],
                    platform=row["Platform"],
                )
            except Exception as e:
                print(f"Error on sample {idx}: {e}")
                continue

        results_df = pd.DataFrame(self.ate_results)

        print(f"\nCompleted evaluation of {len(self.ate_results)} samples")
        return results_df

    def get_ate_summary(self) -> Dict:
        """
        Get summary statistics for CTI-ATE evaluation.

        Returns:
            Dictionary with macro and micro averaged metrics
        """
        if not self.ate_results:
            return {}

        df = pd.DataFrame(self.ate_results)

        # Macro averages (average of per-sample metrics)
        macro_metrics = {
            "macro_precision": df["precision"].mean(),
            "macro_recall": df["recall"].mean(),
            "macro_f1": df["f1"].mean(),
        }

        # Micro averages (calculated from total TP, FP, FN)
        total_tp = df["tp"].sum()
        total_fp = df["fp"].sum()
        total_fn = df["fn"].sum()
        total_predicted = df["predicted_count"].sum()
        total_gt = df["ground_truth_count"].sum()

        micro_precision = total_tp / total_predicted if total_predicted > 0 else 0.0
        micro_recall = total_tp / total_gt if total_gt > 0 else 0.0
        micro_f1 = (
            2 * (micro_precision * micro_recall) / (micro_precision + micro_recall)
            if (micro_precision + micro_recall) > 0
            else 0.0
        )

        micro_metrics = {
            "micro_precision": micro_precision,
            "micro_recall": micro_recall,
            "micro_f1": micro_f1,
            "total_samples": len(self.ate_results),
            "total_tp": int(total_tp),
            "total_fp": int(total_fp),
            "total_fn": int(total_fn),
        }

        return {**macro_metrics, **micro_metrics}

    # ==================== CTI-TAA: Threat Actor Attribution Tool ====================

    def normalize_actor_name(self, name: str) -> str:
        """
        Normalize threat actor names for comparison.

        Args:
            name: Threat actor name

        Returns:
            Normalized name (lowercase, trimmed)
        """
        if not name:
            return ""

        # Convert to lowercase and strip
        normalized = name.lower().strip()

        # Remove common prefixes
        prefixes = ["apt", "apt-", "group", "the "]
        for prefix in prefixes:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :].strip()

        return normalized

    def extract_actor_from_output(self, text: str) -> str:
        """
        Extract threat actor name from tool output.

        Args:
            text: Tool output text

        Returns:
            Extracted actor name or empty string
        """
        # Look for Q&A format from our updated prompt
        qa_patterns = [
            r"Q:\s*What threat actor.*?\n\s*A:\s*([^\n]+)",
            r"threat actor.*?is[:\s]+([A-Z][A-Za-z0-9\s\-]+?)(?:\s*\(|,|\.|$)",
            r"attributed to[:\s]+([A-Z][A-Za-z0-9\s\-]+?)(?:\s*\(|,|\.|$)",
        ]

        for pattern in qa_patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                actor = match.group(1).strip()
                # Clean up common artifacts
                actor = actor.split("(")[0].strip()  # Remove parenthetical aliases
                if actor and actor.lower() not in [
                    "none",
                    "none identified",
                    "unknown",
                    "not specified",
                ]:
                    return actor

        return ""

    def check_actor_match(
        self, predicted: str, ground_truth: str, aliases: Dict[str, List[str]] = None
    ) -> bool:
        """
        Check if predicted actor matches ground truth, considering aliases.

        Args:
            predicted: Predicted threat actor name
            ground_truth: Ground truth threat actor name
            aliases: Optional dictionary mapping canonical names to aliases

        Returns:
            True if match, False otherwise
        """
        pred_norm = self.normalize_actor_name(predicted)
        gt_norm = self.normalize_actor_name(ground_truth)

        if not pred_norm or not gt_norm:
            return False

        # Direct match
        if pred_norm == gt_norm:
            return True

        # Check aliases if provided
        if aliases:
            # Check if prediction is in ground truth's aliases
            if gt_norm in aliases:
                for alias in aliases[gt_norm]:
                    if pred_norm == self.normalize_actor_name(alias):
                        return True

            # Check if ground truth is in prediction's aliases
            if pred_norm in aliases:
                for alias in aliases[pred_norm]:
                    if gt_norm == self.normalize_actor_name(alias):
                        return True

        return False

    def evaluate_threat_actor_tool(
        self,
        sample_id: str,
        report_text: str,
        ground_truth: str,
        aliases: Dict[str, List[str]] = None,
    ) -> Dict:
        """
        Evaluate identify_threat_actors tool on a single sample.

        Args:
            sample_id: Sample identifier (e.g., URL)
            report_text: Threat report text to analyze
            ground_truth: Ground truth threat actor name
            aliases: Optional alias dictionary for matching

        Returns:
            Dictionary with evaluation result
        """
        print(f"Evaluating {sample_id[:60]}...")

        # Call the identify_threat_actors tool
        tool_output = self.cti_tools.identify_threat_actors(report_text)

        # Extract predicted actor
        predicted_actor = self.extract_actor_from_output(tool_output)

        # Check if match
        is_correct = self.check_actor_match(predicted_actor, ground_truth, aliases)

        result = {
            "sample_id": sample_id,
            "report_snippet": report_text[:100] + "...",
            "tool_output": tool_output[:500] + "...",  # Truncate for storage
            "predicted_actor": predicted_actor,
            "ground_truth": ground_truth,
            "correct": is_correct,
        }

        self.taa_results.append(result)
        return result

    def evaluate_taa_from_tsv(
        self,
        filepath: str = "cti-bench/data/cti-taa.tsv",
        limit: int = None,
        interactive: bool = True,
    ) -> pd.DataFrame:
        """
        Evaluate identify_threat_actors tool on CTI-TAA benchmark.

        Since CTI-TAA has no ground truth labels, this generates predictions
        that need manual validation.

        Args:
            filepath: Path to CTI-TAA TSV file
            limit: Optional limit on number of samples to evaluate
            interactive: If True, prompts for manual validation after each prediction

        Returns:
            DataFrame with results for each sample
        """
        print(f"\n{'='*80}")
        print(f"Evaluating identify_threat_actors tool on CTI-TAA benchmark")
        print(f"{'='*80}\n")

        if not interactive:
            print("NOTE: Running in non-interactive mode.")
            print("Predictions will be saved for manual review later.")
        else:
            print("NOTE: Running in interactive mode.")
            print("You will be asked to validate each prediction (y/n/s to skip).")

        # Load benchmark
        df = pd.read_csv(filepath, sep="\t")

        if limit:
            df = df.head(limit)

        print(f"\nLoaded {len(df)} samples from {filepath}")
        print(f"Starting evaluation...\n")

        # Evaluate each sample
        for idx, row in df.iterrows():
            try:
                print(f"\n{'-'*80}")
                print(f"Sample {idx + 1}/{len(df)}")
                print(f"URL: {row['URL']}")
                print(f"Report snippet: {row['Text'][:200]}...")
                print(f"{'-'*80}")

                # Call the identify_threat_actors tool
                tool_output = self.cti_tools.identify_threat_actors(row["Text"])

                # Extract predicted actor
                predicted_actor = self.extract_actor_from_output(tool_output)

                print(f"\nTOOL OUTPUT:")
                print(tool_output[:600])
                if len(tool_output) > 600:
                    print("... (truncated)")

                print(
                    f"\nEXTRACTED ACTOR: {predicted_actor if predicted_actor else '(none detected)'}"
                )

                # Manual validation
                is_correct = None
                validator_notes = ""

                if interactive:
                    print(f"\nIs this attribution correct?")
                    print(f"  y = Yes, correct")
                    print(f"  n = No, incorrect")
                    print(
                        f"  p = Partially correct (e.g., right family but wrong specific group)"
                    )
                    print(f"  s = Skip this sample")
                    print(f"  q = Quit evaluation")

                    while True:
                        response = input("\nYour answer [y/n/p/s/q]: ").strip().lower()

                        if response == "y":
                            is_correct = True
                            break
                        elif response == "n":
                            is_correct = False
                            correct_actor = input(
                                "What is the correct actor? (optional): "
                            ).strip()
                            if correct_actor:
                                validator_notes = f"Correct actor: {correct_actor}"
                            break
                        elif response == "p":
                            is_correct = 0.5  # Partial credit
                            note = input("Explanation (optional): ").strip()
                            if note:
                                validator_notes = f"Partially correct: {note}"
                            break
                        elif response == "s":
                            print("Skipping this sample...")
                            break
                        elif response == "q":
                            print("Quitting evaluation...")
                            return pd.DataFrame(self.taa_results)
                        else:
                            print("Invalid response. Please enter y, n, p, s, or q.")

                # Store result
                result = {
                    "sample_id": row["URL"],
                    "report_snippet": row["Text"][:100] + "...",
                    "tool_output": tool_output[:500] + "...",
                    "predicted_actor": predicted_actor,
                    "is_correct": is_correct,
                    "validator_notes": validator_notes,
                    "needs_review": is_correct is None,
                }

                self.taa_results.append(result)

            except Exception as e:
                print(f"Error on sample {idx}: {e}")
                continue

        results_df = pd.DataFrame(self.taa_results)

        print(f"\n{'='*80}")
        print(f"Completed evaluation of {len(self.taa_results)} samples")

        if interactive:
            validated = sum(1 for r in self.taa_results if r["is_correct"] is not None)
            print(f"Validated: {validated}/{len(self.taa_results)}")

        return results_df

    def _extract_ground_truths_from_urls(self, urls: List[str]) -> Dict[str, str]:
        """
        Extract ground truth actor names from URLs.

        Args:
            urls: List of URLs from the benchmark

        Returns:
            Dictionary mapping URL to actor name
        """
        # Known threat actors and their URL patterns
        actor_patterns = {
            "sidecopy": "SideCopy",
            "apt29": "APT29",
            "apt36": "APT36",
            "transparent-tribe": "Transparent Tribe",
            "emotet": "Emotet",
            "bandook": "Bandook",
            "stately-taurus": "Stately Taurus",
            "mustang-panda": "Mustang Panda",
            "bronze-president": "Bronze President",
            "cozy-bear": "APT29",
            "nobelium": "APT29",
        }

        ground_truths = {}
        for url in urls:
            url_lower = url.lower()
            for pattern, actor in actor_patterns.items():
                if pattern in url_lower:
                    ground_truths[url] = actor
                    break

        return ground_truths

    def get_taa_summary(self) -> Dict:
        """
        Get summary statistics for CTI-TAA evaluation.

        Returns:
            Dictionary with accuracy and validation status
        """
        if not self.taa_results:
            return {}

        df = pd.DataFrame(self.taa_results)

        # Only calculate metrics for validated samples
        validated_df = df[df["is_correct"].notna()]

        if len(validated_df) == 0:
            return {
                "total_samples": len(df),
                "validated_samples": 0,
                "needs_review": len(df),
                "message": "No samples have been validated yet",
            }

        # Calculate accuracy (treating partial credit as 0.5)
        total_score = validated_df["is_correct"].sum()
        accuracy = total_score / len(validated_df) if len(validated_df) > 0 else 0.0

        # Count correct, incorrect, partial
        correct = sum(1 for x in validated_df["is_correct"] if x == True)
        incorrect = sum(1 for x in validated_df["is_correct"] if x == False)
        partial = sum(1 for x in validated_df["is_correct"] if x == 0.5)

        return {
            "accuracy": accuracy,
            "total_samples": len(df),
            "validated_samples": len(validated_df),
            "needs_review": len(df) - len(validated_df),
            "correct": correct,
            "incorrect": incorrect,
            "partial": partial,
        }

    # ==================== Utility Functions ====================

    def export_results(self, output_dir: str = "./tool_evaluation_results"):
        """
        Export evaluation results to CSV and JSON files.

        Args:
            output_dir: Directory to save results
        """
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        if self.ate_results:
            ate_df = pd.DataFrame(self.ate_results)
            ate_df.to_csv(
                output_path / "extract_mitre_techniques_results.csv", index=False
            )

            ate_summary = self.get_ate_summary()
            with open(output_path / "extract_mitre_techniques_summary.json", "w") as f:
                json.dump(ate_summary, f, indent=2)

            print(f"ATE results saved to {output_path}")

        if self.taa_results:
            taa_df = pd.DataFrame(self.taa_results)
            taa_df.to_csv(
                output_path / "identify_threat_actors_results.csv", index=False
            )

            taa_summary = self.get_taa_summary()
            with open(output_path / "identify_threat_actors_summary.json", "w") as f:
                json.dump(taa_summary, f, indent=2)

            print(f"TAA results saved to {output_path}")

    def print_summary(self):
        """Print summary of both tool evaluations."""
        print("\n" + "=" * 80)
        print("extract_mitre_techniques Tool Evaluation (CTI-ATE)")
        print("=" * 80)

        ate_summary = self.get_ate_summary()
        if ate_summary:
            print(f"Total Samples: {ate_summary['total_samples']}")
            print(f"\nMacro Averages (per-sample average):")
            print(f"  Precision: {ate_summary['macro_precision']:.4f}")
            print(f"  Recall:    {ate_summary['macro_recall']:.4f}")
            print(f"  F1 Score:  {ate_summary['macro_f1']:.4f}")
            print(f"\nMicro Averages (overall corpus):")
            print(f"  Precision: {ate_summary['micro_precision']:.4f}")
            print(f"  Recall:    {ate_summary['micro_recall']:.4f}")
            print(f"  F1 Score:  {ate_summary['micro_f1']:.4f}")
            print(f"\nConfusion Matrix:")
            print(f"  True Positives:  {ate_summary['total_tp']}")
            print(f"  False Positives: {ate_summary['total_fp']}")
            print(f"  False Negatives: {ate_summary['total_fn']}")
        else:
            print("No results available.")

        print("\n" + "=" * 80)
        print("identify_threat_actors Tool Evaluation (CTI-TAA)")
        print("=" * 80)

        taa_summary = self.get_taa_summary()
        if taa_summary:
            print(f"Total Samples: {taa_summary['total_samples']}")
            print(
                f"Accuracy: {taa_summary['accuracy']:.4f} ({taa_summary['accuracy']*100:.2f}%)"
            )
            print(f"Correct: {taa_summary['correct']}")
            print(f"Incorrect: {taa_summary['incorrect']}")
        else:
            print("No results available.")

        print("=" * 80 + "\n")


# ==================== Main Evaluation Script ====================

if __name__ == "__main__":
    """Run evaluation on both CTI tools."""

    # Initialize evaluator
    print("Initializing CTI Tools Evaluator...")
    evaluator = CTIToolsEvaluator()

    # Define threat actor aliases for TAA evaluation
    aliases = {
        "apt29": ["cozy bear", "the dukes", "nobelium", "yttrium"],
        "apt36": ["transparent tribe", "mythic leopard"],
        "sidecopy": [],
        "emotet": [],
        "stately taurus": ["mustang panda", "bronze president"],
        "bandook": [],
    }

    # Evaluate extract_mitre_techniques tool (CTI-ATE)
    print("\n" + "=" * 80)
    print("PART 1: Evaluating extract_mitre_techniques tool")
    print("=" * 80)
    try:
        ate_results = evaluator.evaluate_ate_from_tsv(
            filepath="cti-bench/data/cti-ate.tsv"
        )
    except Exception as e:
        print(f"Error evaluating ATE: {e}")

    # Evaluate identify_threat_actors tool (CTI-TAA)
    print("\n" + "=" * 80)
    print("PART 2: Evaluating identify_threat_actors tool")
    print("=" * 80)
    try:
        taa_results = evaluator.evaluate_taa_from_tsv(
            filepath="cti-bench/data/cti-taa.tsv", limit=25, interactive=True
        )
    except Exception as e:
        print(f"Error evaluating TAA: {e}")

    # Print summary
    evaluator.print_summary()

    # Export results
    evaluator.export_results("./tool_evaluation_results")

    print("\nEvaluation complete! Results saved to ./tool_evaluation_results/")
