"""
CTI Bench Evaluation Script for Cybersecurity Retrieval System

This script evaluates the retrieval supervisor system against the CTI Bench dataset,
including both CTI-ATE (attack technique extraction) and CTI-MCQ (multiple choice questions).
"""

import os
import sys
import pandas as pd
import re
import json
import csv
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score
import numpy as np

# Import your supervisor
from src.agents.retrieval_supervisor.supervisor import RetrievalSupervisor


class CTIBenchEvaluator:
    """Evaluator for CTI Bench dataset using the Retrieval Supervisor."""

    def __init__(
        self,
        supervisor: Optional[RetrievalSupervisor],
        dataset_dir: str = "cti_bench/datasets",
        output_dir: str = "cti_bench/eval_output",
    ):
        """
        Initialize the CTI Bench evaluator.

        Args:
            supervisor: RetrievalSupervisor instance (can be None for CSV processing)
            dataset_dir: Directory containing CTI Bench datasets
            output_dir: Directory to save evaluation results
        """
        self.supervisor = supervisor
        self.dataset_dir = Path(dataset_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Templates for queries
        self.ate_query_template = """You are a cybersecurity expert specializing in cyber threat intelligence. 
Extract all MITRE Enterprise attack patterns from the following text and map them to their corresponding MITRE technique IDs. 
Provide reasoning for each identification. 
Ensure the final line contains only the IDs for the main techniques, separated by commas, excluding any subtechnique IDs.

Example of the final line: T1071, T1560, T1547

Text:
{attack_description}
"""

    def load_datasets(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Load CTI-ATE and CTI-MCQ datasets."""
        try:
            # Load CTI-ATE dataset
            ate_path = self.dataset_dir / "cti-ate.tsv"
            ate_df = pd.read_csv(ate_path, sep="\t")
            print(f"Loaded CTI-ATE dataset: {len(ate_df)} samples")

            # Load CTI-MCQ dataset
            mcq_path = self.dataset_dir / "cti-mcq.tsv"
            mcq_df = pd.read_csv(mcq_path, sep="\t")
            print(f"Loaded CTI-MCQ dataset: {len(mcq_df)} samples")

            return ate_df, mcq_df

        except Exception as e:
            print(f"Error loading datasets: {e}")
            raise

    def filter_dataset(self, df: pd.DataFrame, dataset_type: str) -> pd.DataFrame:
        """Filter dataset according to requirements."""
        if dataset_type == "ate":
            # Filter ATE: only Enterprise platform
            filtered_df = df[df["Platform"] == "Enterprise"].copy()
            print(
                f"CTI-ATE filtered to Enterprise platform: {len(filtered_df)} samples"
            )
        elif dataset_type == "mcq":
            # Filter MCQ: only samples with "techniques" in URL
            filtered_df = df[df["URL"].str.contains("techniques", na=False)].copy()
            print(f"CTI-MCQ filtered to technique URLs: {len(filtered_df)} samples")
        else:
            raise ValueError(f"Invalid dataset type: {dataset_type}")

        return filtered_df

    def extract_technique_ids_from_response(self, response: str) -> List[str]:
        """
        Extract MITRE technique IDs from the response text.
        Simplified version: only checks the final line.

        Args:
            response: Response text from the supervisor

        Returns:
            List of extracted technique IDs, or empty list if not successful
        """
        # Get the final line
        lines = response.strip().split("\n")
        if not lines:
            return []

        final_line = lines[-1].strip()
        if not final_line:
            return []

        # Pattern to match MITRE technique IDs (T followed by 4 digits, optionally followed by .XXX)
        technique_pattern = r"\bT\d{4}(?:\.\d{3})?\b"

        # Check if final line contains only technique IDs, commas, and spaces
        techniques_in_line = re.findall(technique_pattern, final_line)
        if not techniques_in_line:
            return []

        # Check if the line is only technique IDs, commas, and spaces
        clean_line = re.sub(r"[T\d.,\s]", "", final_line)
        if len(clean_line) > 0:
            return []  # Not successful - line contains other characters

        # Return all technique IDs from the final line (excluding subtechniques)
        return [t for t in techniques_in_line if "." not in t]

    def extract_mcq_answer_from_response(self, response: str) -> str:
        """
        Extract the final answer (A, B, C, or D) from MCQ response.

        Args:
            response: Response text from the supervisor

        Returns:
            Extracted answer letter or empty string if not found
        """
        # Look for single letter answers at the end of lines
        lines = response.strip().split("\n")

        # Check the last few lines for a single letter answer
        for line in reversed(lines[-3:]):
            line = line.strip()
            if line in ["A", "B", "C", "D"]:
                return line

            # Check for patterns like "Answer: A" or "The answer is B"
            match = re.search(r"\b([ABCD])\b(?:\s*[.)]?)\s*$", line)
            if match:
                return match.group(1)

        # Fallback: search the entire response for answer patterns
        answer_patterns = [
            r"(?:answer|choice|option).*?([ABCD])",
            r"\b([ABCD])\b(?:\s*[.)]?)\s*$",
            r"^([ABCD])$",
        ]

        for pattern in answer_patterns:
            matches = re.findall(pattern, response, re.IGNORECASE | re.MULTILINE)
            if matches:
                return matches[-1].upper()

        return ""  # No answer found

    def evaluate_ate_dataset(self, ate_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Evaluate the CTI-ATE dataset.

        Args:
            ate_df: Filtered CTI-ATE dataset

        Returns:
            List of evaluation results
        """
        results = []

        print(f"\n{'='*60}")
        print("EVALUATING CTI-ATE DATASET")
        print(f"{'='*60}")

        for i, (idx, row) in enumerate(ate_df.iterrows()):
            print(f"Processing ATE sample {i + 1}/{len(ate_df)}: {row['URL']}")

            # Retry up to 3 times for each sample
            max_retries = 3
            success = False
            result = None

            for attempt in range(max_retries):
                try:
                    print(f"  Attempt {attempt + 1}/{max_retries}")

                    # Create query from template
                    query = self.ate_query_template.format(
                        attack_description=row["Description"]
                    )

                    # Get response from supervisor
                    response = self.supervisor.invoke_direct_query(query, trace=False)

                    # Extract final message content from LangGraph result
                    if "messages" in response and response["messages"]:
                        # Get the last AI message from the conversation
                        last_message = None
                        for msg in reversed(response["messages"]):
                            try:
                                if (
                                    hasattr(msg, "content")
                                    and hasattr(msg, "type")
                                    and msg.type == "ai"
                                ):
                                    last_message = msg
                                    break
                            except (AttributeError, TypeError) as e:
                                # Handle cases where msg.type might be an int instead of string
                                print(f"  Warning: Error accessing message type: {e}")
                                continue

                        if last_message:
                            response_text = last_message.content
                        else:
                            # Fallback: get the last message regardless of type
                            try:
                                response_text = response["messages"][-1].content
                            except (AttributeError, TypeError) as e:
                                print(
                                    f"  Warning: Error accessing last message content: {e}"
                                )
                                response_text = str(response["messages"][-1])
                    else:
                        response_text = str(response)

                    # Extract technique IDs from response
                    predicted_techniques = self.extract_technique_ids_from_response(
                        response_text
                    )

                    # Parse ground truth
                    gt_techniques = [
                        t.strip() for t in row["GT"].split(",") if t.strip()
                    ]

                    # Check if extraction was successful
                    if len(predicted_techniques) > 0:
                        success = True
                        result = {
                            "url": row["URL"],
                            "description": row["Description"],
                            "ground_truth": gt_techniques,
                            "predicted": predicted_techniques,
                            "response_text": response_text,
                            "success": True,
                            "attempts": attempt + 1,
                        }
                        print(f"  GT: {gt_techniques}")
                        print(f"  Predicted: {predicted_techniques}")
                        print(f"  Success: {result['success']} (attempt {attempt + 1})")
                        break
                    else:
                        print(f"  No techniques extracted on attempt {attempt + 1}")
                        if attempt == max_retries - 1:
                            # Final attempt failed
                            result = {
                                "url": row["URL"],
                                "description": row["Description"],
                                "ground_truth": gt_techniques,
                                "predicted": [],
                                "response_text": response_text,
                                "success": False,
                                "attempts": max_retries,
                            }
                            print(f"  GT: {gt_techniques}")
                            print(f"  Predicted: {predicted_techniques}")
                            print(
                                f"  Success: {result['success']} (all attempts failed)"
                            )
                            print(f"  Response text: {response_text}")

                except Exception as e:
                    print(f"  Error processing sample (attempt {attempt + 1}): {e}")
                    if attempt == max_retries - 1:
                        # Final attempt failed
                        result = {
                            "url": row["URL"],
                            "description": row["Description"],
                            "ground_truth": [
                                t.strip() for t in row["GT"].split(",") if t.strip()
                            ],
                            "predicted": [],
                            "response_text": f"Error: {str(e)}",
                            "success": False,
                            "attempts": max_retries,
                        }
                        print(f"  Success: {result['success']} (all attempts failed)")
            results.append(result)

        return results

    def evaluate_mcq_dataset(self, mcq_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Evaluate the CTI-MCQ dataset.

        Args:
            mcq_df: Filtered CTI-MCQ dataset

        Returns:
            List of evaluation results
        """
        results = []

        print(f"\n{'='*60}")
        print("EVALUATING CTI-MCQ DATASET")
        print(f"{'='*60}")

        for i, (idx, row) in enumerate(mcq_df.iterrows()):
            print(f"Processing MCQ sample {i + 1}/{len(mcq_df)}: {row['URL']}")

            try:
                # Use the provided prompt
                query = row["Prompt"]

                # Get response from supervisor
                response = self.supervisor.invoke_direct_query(query, trace=False)

                # Extract final message content from LangGraph result
                if "messages" in response and response["messages"]:
                    # Get the last AI message from the conversation
                    last_message = None
                    for msg in reversed(response["messages"]):
                        try:
                            if (
                                hasattr(msg, "content")
                                and hasattr(msg, "type")
                                and msg.type == "ai"
                            ):
                                last_message = msg
                                break
                        except (AttributeError, TypeError) as e:
                            # Handle cases where msg.type might be an int instead of string
                            print(f"  Warning: Error accessing message type: {e}")
                            continue

                    if last_message:
                        response_text = last_message.content
                    else:
                        # Fallback: get the last message regardless of type
                        try:
                            response_text = response["messages"][-1].content
                        except (AttributeError, TypeError) as e:
                            print(
                                f"  Warning: Error accessing last message content: {e}"
                            )
                            response_text = str(response["messages"][-1])
                else:
                    response_text = str(response)

                # Extract answer from response
                predicted_answer = self.extract_mcq_answer_from_response(response_text)

                # Ground truth answer
                gt_answer = row["GT"].strip().upper()

                # Store result
                result = {
                    "url": row["URL"],
                    "prompt": row["Prompt"],
                    "ground_truth": gt_answer,
                    "predicted": predicted_answer,
                    "response_text": response_text,
                    "correct": predicted_answer == gt_answer,
                    "success": len(predicted_answer) > 0,
                }

                results.append(result)

                print(f"  GT: {gt_answer}")
                print(f"  Predicted: {predicted_answer}")
                print(f"  Correct: {result['correct']}")

            except Exception as e:
                print(f"  Error processing sample: {e}")
                result = {
                    "url": row["URL"],
                    "prompt": row["Prompt"],
                    "ground_truth": row["GT"].strip().upper(),
                    "predicted": "",
                    "response_text": f"Error: {str(e)}",
                    "correct": False,
                    "success": False,
                }
                results.append(result)

        return results

    def calculate_ate_metrics(self, results: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Calculate evaluation metrics for ATE dataset using sample-level metrics.

        Args:
            results: List of ATE evaluation results

        Returns:
            Dictionary of calculated metrics
        """
        if not results:
            return {}

        # Collect all unique technique IDs
        all_techniques = set()
        for result in results:
            all_techniques.update(result["ground_truth"])
            all_techniques.update(result["predicted"])

        all_techniques = sorted(list(all_techniques))

        # Sample-level metrics (macro = average across samples)
        sample_precisions = []
        sample_recalls = []
        sample_f1s = []

        for result in results:
            gt_set = set(result["ground_truth"])
            pred_set = set(result["predicted"])

            # Calculate precision, recall, and F1 for this sample
            if len(pred_set) == 0:
                precision = 0.0
            else:
                precision = len(gt_set.intersection(pred_set)) / len(pred_set)

            if len(gt_set) == 0:
                recall = 1.0 if len(pred_set) == 0 else 0.0
            else:
                recall = len(gt_set.intersection(pred_set)) / len(gt_set)

            if precision + recall == 0:
                f1 = 0.0
            else:
                f1 = 2 * (precision * recall) / (precision + recall)

            sample_precisions.append(precision)
            sample_recalls.append(recall)
            sample_f1s.append(f1)

        # Calculate macro-averaged metrics (average across samples)
        macro_precision = np.mean(sample_precisions)
        macro_recall = np.mean(sample_recalls)
        macro_f1 = np.mean(sample_f1s)

        # Sample-level micro metrics (aggregate TP, FP, FN across all samples)
        total_tp = 0
        total_fp = 0
        total_fn = 0

        for result in results:
            gt_set = set(result["ground_truth"])
            pred_set = set(result["predicted"])

            tp = len(gt_set.intersection(pred_set))
            fp = len(pred_set - gt_set)
            fn = len(gt_set - pred_set)

            total_tp += tp
            total_fp += fp
            total_fn += fn

        # Calculate micro-averaged metrics
        if total_tp + total_fp == 0:
            micro_precision = 0.0
        else:
            micro_precision = total_tp / (total_tp + total_fp)

        if total_tp + total_fn == 0:
            micro_recall = 0.0
        else:
            micro_recall = total_tp / (total_tp + total_fn)

        if micro_precision + micro_recall == 0:
            micro_f1 = 0.0
        else:
            micro_f1 = (
                2 * (micro_precision * micro_recall) / (micro_precision + micro_recall)
            )

        # Additional metrics
        exact_match = sum(
            1 for r in results if set(r["ground_truth"]) == set(r["predicted"])
        ) / len(results)
        success_rate = sum(1 for r in results if r["success"]) / len(results)

        return {
            # Primary metrics (sample-level)
            "macro_f1": macro_f1,
            "macro_precision": macro_precision,
            "macro_recall": macro_recall,
            "micro_f1": micro_f1,
            "micro_precision": micro_precision,
            "micro_recall": micro_recall,
            # Additional metrics
            "exact_match_ratio": exact_match,
            "success_rate": success_rate,
            "total_samples": len(results),
            "total_techniques": len(all_techniques),
        }

    def calculate_mcq_metrics(self, results: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Calculate evaluation metrics for MCQ dataset.

        Args:
            results: List of MCQ evaluation results

        Returns:
            Dictionary of calculated metrics
        """
        if not results:
            return {}

        # Prepare labels for sklearn metrics
        y_true = []
        y_pred = []

        for result in results:
            if result["success"]:  # Only include samples where we got a prediction
                y_true.append(result["ground_truth"])
                y_pred.append(result["predicted"])

        if not y_true:
            return {
                "accuracy": 0.0,
                "f1_macro": 0.0,
                "f1_micro": 0.0,
                "precision_macro": 0.0,
                "recall_macro": 0.0,
                "success_rate": 0.0,
                "total_samples": len(results),
                "answered_samples": 0,
            }

        # Calculate metrics
        accuracy = accuracy_score(y_true, y_pred)
        f1_macro = f1_score(y_true, y_pred, average="macro", zero_division=0)
        f1_micro = f1_score(y_true, y_pred, average="micro", zero_division=0)
        precision_macro = precision_score(
            y_true, y_pred, average="macro", zero_division=0
        )
        recall_macro = recall_score(y_true, y_pred, average="macro", zero_division=0)

        success_rate = sum(1 for r in results if r["success"]) / len(results)

        return {
            "accuracy": accuracy,
            "f1_macro": f1_macro,
            "f1_micro": f1_micro,
            "precision_macro": precision_macro,
            "recall_macro": recall_macro,
            "success_rate": success_rate,
            "total_samples": len(results),
            "answered_samples": len(y_true),
        }

    def save_results_to_csv(
        self, results: List[Dict[str, Any]], dataset_type: str, model_name: str = None
    ):
        """
        Save evaluation results to CSV file.

        Args:
            results: Evaluation results
            dataset_type: Type of dataset ("ate" or "mcq")
            model_name: Model name (if None, extracted from supervisor)
        """
        if model_name is None:
            if self.supervisor is not None:
                model_name = self.supervisor.llm_model.split(":")[-1]
            else:
                model_name = "unknown_model"

        # Sanitize model name for filename
        sanitized_model_name = self._sanitize_filename(model_name)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if dataset_type == "ate":
            csv_path = (
                self.output_dir / f"cti-ate_{sanitized_model_name}_{timestamp}.csv"
            )
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Description", "GT", "Predicted"])

                for result in results:
                    description = result["description"]
                    gt = ", ".join(result["ground_truth"])
                    predicted = ", ".join(result["predicted"])
                    writer.writerow([description, gt, predicted])

            print(f"ATE results saved to: {csv_path}")

        elif dataset_type == "mcq":
            csv_path = (
                self.output_dir / f"cti-mcq_{sanitized_model_name}_{timestamp}.csv"
            )
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Prompt", "GT", "Predicted"])

                for result in results:
                    prompt = result["prompt"]
                    writer.writerow(
                        [prompt, result["ground_truth"], result["predicted"]]
                    )

            print(f"MCQ results saved to: {csv_path}")
        else:
            raise ValueError(f"Invalid dataset type: {dataset_type}")

    def save_evaluation_summary(
        self, metrics: Dict[str, float], dataset_type: str, model_name: str = None
    ):
        """
        Save evaluation summary to JSON file.

        Args:
            metrics: Evaluation metrics
            dataset_type: Type of dataset ("ate" or "mcq")
            model_name: Model name (if None, extracted from supervisor)
        """
        if model_name is None:
            if self.supervisor is not None:
                model_name = self.supervisor.llm_model.split(":")[-1]
            else:
                model_name = "unknown_model"

        # Sanitize model name for filename
        sanitized_model_name = self._sanitize_filename(model_name)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary = {
            "evaluation_timestamp": datetime.now().isoformat(),
            "dataset_type": dataset_type,
            "model_name": model_name,  # Keep original model name in JSON content
            "metrics": metrics,
        }

        summary_path = (
            self.output_dir
            / f"evaluation_summary_{dataset_type}_{sanitized_model_name}_{timestamp}.json"
        )
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print(f"Evaluation summary saved to: {summary_path}")

    def _extract_dataset_type_from_filename(self, filename: str) -> str:
        """
        Extract dataset type from CSV filename.

        Args:
            filename: The filename (without extension) to extract dataset type from

        Returns:
            Dataset type ("ate" or "mcq")
        """
        if "cti-ate" in filename.lower():
            return "ate"
        elif "cti-mcq" in filename.lower():
            return "mcq"
        else:
            raise ValueError(f"Cannot determine dataset type from filename: {filename}")

    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize a string to be safe for use in filenames.

        Args:
            filename: The string to sanitize

        Returns:
            Sanitized filename string
        """
        import re

        # Replace invalid characters with dashes
        sanitized = re.sub(r'[/\\:*?"<>|]', "-", filename)

        # Remove any leading/trailing dashes and multiple consecutive dashes
        sanitized = re.sub(r"-+", "-", sanitized).strip("-")

        return sanitized if sanitized else "unknown"

    def read_csv_results(
        self, csv_path: str, dataset_type: str
    ) -> List[Dict[str, Any]]:
        """
        Read existing CSV results and convert to evaluation results format.

        Args:
            csv_path: Path to the CSV file
            dataset_type: Type of dataset ("ate" or "mcq")

        Returns:
            List of evaluation results in the same format as evaluate_*_dataset methods
        """
        try:
            df = pd.read_csv(csv_path)
            results = []

            if dataset_type == "ate":
                # Expected columns: Description, GT, Predicted
                for _, row in df.iterrows():
                    # Parse ground truth and predicted techniques
                    gt_techniques = [
                        t.strip() for t in str(row["GT"]).split(",") if t.strip()
                    ]
                    predicted_techniques = [
                        t.strip() for t in str(row["Predicted"]).split(",") if t.strip()
                    ]

                    result = {
                        "url": f"csv_row_{len(results)}",  # Placeholder URL
                        "description": str(row["Description"]),
                        "ground_truth": gt_techniques,
                        "predicted": predicted_techniques,
                        "response_text": f"GT: {', '.join(gt_techniques)}, Predicted: {', '.join(predicted_techniques)}",
                        "success": len(predicted_techniques) > 0,
                        "attempts": 1,
                    }
                    results.append(result)

            elif dataset_type == "mcq":
                # Expected columns: Prompt, GT, Predicted
                for _, row in df.iterrows():
                    gt_answer = str(row["GT"]).strip().upper()
                    predicted_answer = str(row["Predicted"]).strip().upper()

                    result = {
                        "url": f"csv_row_{len(results)}",  # Placeholder URL
                        "prompt": str(row["Prompt"]),
                        "ground_truth": gt_answer,
                        "predicted": predicted_answer,
                        "response_text": f"GT: {gt_answer}, Predicted: {predicted_answer}",
                        "correct": predicted_answer == gt_answer,
                        "success": len(predicted_answer) > 0,
                    }
                    results.append(result)

            else:
                raise ValueError(f"Invalid dataset type: {dataset_type}")

            print(f"Successfully read {len(results)} results from {csv_path}")
            return results

        except Exception as e:
            print(f"Error reading CSV file {csv_path}: {e}")
            raise

    def calculate_metrics_from_csv(
        self, csv_path: str, model_name: str = None
    ) -> Dict[str, Any]:
        """
        Read existing CSV results, calculate metrics, and save summary.

        Args:
            csv_path: Path to the CSV file
            model_name: Model name to use in summary (if None, extracted from filename)

        Returns:
            Dictionary containing results and metrics
        """
        # Extract dataset type and model name from filename
        filename = Path(csv_path).stem
        dataset_type = self._extract_dataset_type_from_filename(filename)

        if model_name is None:
            # Try to extract model name from filename (e.g., cti-ate_gemini-2.0-flash_20251024_193022)
            parts = filename.split("_")
            if len(parts) >= 2:
                model_name = parts[1]  # Second part should be model name
            else:
                model_name = "unknown_model"

        print(f"Processing CSV file: {csv_path}")
        print(f"Dataset type: {dataset_type} (extracted from filename)")
        print(f"Model name: {model_name}")

        # Read results from CSV
        results = self.read_csv_results(csv_path, dataset_type)

        # Calculate metrics
        if dataset_type == "ate":
            metrics = self.calculate_ate_metrics(results)
        elif dataset_type == "mcq":
            metrics = self.calculate_mcq_metrics(results)
        else:
            raise ValueError(f"Invalid dataset type: {dataset_type}")

        # Save evaluation summary
        sanitized_model_name = self._sanitize_filename(model_name)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary = {
            "evaluation_timestamp": datetime.now().isoformat(),
            "dataset_type": dataset_type,
            "model_name": model_name,  # Keep original model name in JSON content
            "source_csv": csv_path,
            "metrics": metrics,
        }

        summary_path = (
            self.output_dir
            / f"evaluation_summary_{dataset_type}_{sanitized_model_name}_{timestamp}.json"
        )
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print(f"Evaluation summary saved to: {summary_path}")

        # Print summary of results
        print(f"\n{'='*60}")
        print(f"METRICS FROM CSV: {dataset_type.upper()}")
        print(f"{'='*60}")

        if dataset_type == "ate":
            print(f"Macro F1: {metrics.get('macro_f1', 0.0):.3f}")
            print(f"Macro Precision: {metrics.get('macro_precision', 0.0):.3f}")
            print(f"Macro Recall: {metrics.get('macro_recall', 0.0):.3f}")
            print(f"Micro F1: {metrics.get('micro_f1', 0.0):.3f}")
            print(f"Exact Match: {metrics.get('exact_match_ratio', 0.0):.3f}")
            print(f"Success Rate: {metrics.get('success_rate', 0.0):.3f}")
            print(f"Total Samples: {metrics.get('total_samples', 0)}")
        elif dataset_type == "mcq":
            print(f"Accuracy: {metrics.get('accuracy', 0.0):.3f}")
            print(f"F1 Macro: {metrics.get('f1_macro', 0.0):.3f}")
            print(f"Success Rate: {metrics.get('success_rate', 0.0):.3f}")
            print(f"Total Samples: {metrics.get('total_samples', 0)}")

        print(f"{'='*60}")

        return {
            "results": results,
            "metrics": metrics,
            "summary_path": str(summary_path),
        }

    def run_full_evaluation(self) -> Dict[str, Any]:
        """
        Run the complete evaluation pipeline.

        Returns:
            Dictionary containing all evaluation results and metrics
        """
        print("Starting CTI Bench evaluation...")
        print(f"Output directory: {self.output_dir}")

        # Load and filter datasets
        ate_df, mcq_df = self.load_datasets()
        ate_filtered = self.filter_dataset(ate_df, "ate")
        mcq_filtered = self.filter_dataset(mcq_df, "mcq")

        # Evaluate datasets and calculate metrics for ATE
        ate_results = self.evaluate_ate_dataset(ate_filtered)
        ate_metrics = self.calculate_ate_metrics(ate_results)

        # Evaluate datasets and calculate metrics for MCQ
        mcq_results = self.evaluate_mcq_dataset(mcq_filtered)
        mcq_metrics = self.calculate_mcq_metrics(mcq_results)

        # Save results to CSV files
        self.save_results_to_csv(ate_results, "ate")
        self.save_results_to_csv(mcq_results, "mcq")
        self.save_evaluation_summary(ate_metrics, "ate")
        self.save_evaluation_summary(mcq_metrics, "mcq")

        # Print summary of evaluation results
        print(f"\n{'='*60}")
        print("EVALUATION SUMMARY")
        print(f"{'='*60}")
        print(f"CTI-ATE Results:")
        print(f"  Macro F1: {ate_metrics.get('macro_f1', 0.0):.3f}")
        print(f"  Macro Precision: {ate_metrics.get('macro_precision', 0.0):.3f}")
        print(f"  Macro Recall: {ate_metrics.get('macro_recall', 0.0):.3f}")
        print(f"  Micro F1: {ate_metrics.get('micro_f1', 0.0):.3f}")
        print(f"  Exact Match: {ate_metrics.get('exact_match_ratio', 0.0):.3f}")
        print(f"  Success Rate: {ate_metrics.get('success_rate', 0.0):.3f}")
        print(f"  Total Samples: {ate_metrics.get('total_samples', 0)}")

        print(f"\nCTI-MCQ Results:")
        print(f"  Accuracy: {mcq_metrics.get('accuracy', 0.0):.3f}")
        print(f"  F1 Macro: {mcq_metrics.get('f1_macro', 0.0):.3f}")
        print(f"  Success Rate: {mcq_metrics.get('success_rate', 0.0):.3f}")
        print(f"  Total Samples: {mcq_metrics.get('total_samples', 0)}")
        print(f"{'='*60}")

        return {
            "ate_results": ate_results,
            "mcq_results": mcq_results,
            "ate_metrics": ate_metrics,
            "mcq_metrics": mcq_metrics,
        }

    def run_ate_evaluation(self) -> Dict[str, Any]:
        """
        Run evaluation on ATE dataset only.

        Returns:
            Dictionary containing ATE evaluation results and metrics
        """
        print("Starting CTI-ATE evaluation...")
        print(f"Output directory: {self.output_dir}")

        # Load and filter datasets
        ate_df, mcq_df = self.load_datasets()
        ate_filtered = self.filter_dataset(ate_df, "ate")

        # Evaluate ATE dataset and calculate metrics
        ate_results = self.evaluate_ate_dataset(ate_filtered)
        ate_metrics = self.calculate_ate_metrics(ate_results)

        # Save results to CSV files (ATE only)
        self.save_results_to_csv(ate_results, "ate")
        self.save_evaluation_summary(ate_metrics, "ate")

        # Print summary of evaluation results
        print(f"\n{'='*60}")
        print("CTI-ATE EVALUATION SUMMARY")
        print(f"{'='*60}")
        print(f"CTI-ATE Results:")
        print(f"  Macro F1: {ate_metrics.get('macro_f1', 0.0):.3f}")
        print(f"  Macro Precision: {ate_metrics.get('macro_precision', 0.0):.3f}")
        print(f"  Macro Recall: {ate_metrics.get('macro_recall', 0.0):.3f}")
        print(f"  Micro F1: {ate_metrics.get('micro_f1', 0.0):.3f}")
        print(f"  Exact Match: {ate_metrics.get('exact_match_ratio', 0.0):.3f}")
        print(f"  Success Rate: {ate_metrics.get('success_rate', 0.0):.3f}")
        print(f"  Total Samples: {ate_metrics.get('total_samples', 0)}")
        print(f"{'='*60}")

        return {
            "ate_results": ate_results,
            "ate_metrics": ate_metrics,
        }

    def run_mcq_evaluation(self) -> Dict[str, Any]:
        """
        Run evaluation on MCQ dataset only.

        Returns:
            Dictionary containing MCQ evaluation results and metrics
        """
        print("Starting CTI-MCQ evaluation...")
        print(f"Output directory: {self.output_dir}")

        # Load and filter datasets
        ate_df, mcq_df = self.load_datasets()
        mcq_filtered = self.filter_dataset(mcq_df, "mcq")

        # Evaluate MCQ dataset and calculate metrics
        mcq_results = self.evaluate_mcq_dataset(mcq_filtered)
        mcq_metrics = self.calculate_mcq_metrics(mcq_results)

        # Save results to CSV files (MCQ only)
        self.save_results_to_csv(mcq_results, "mcq")
        self.save_evaluation_summary(mcq_metrics, "mcq")

        # Print summary of evaluation results
        print(f"\n{'='*60}")
        print("CTI-MCQ EVALUATION SUMMARY")
        print(f"{'='*60}")
        print(f"CTI-MCQ Results:")
        print(f"  Accuracy: {mcq_metrics.get('accuracy', 0.0):.3f}")
        print(f"  F1 Macro: {mcq_metrics.get('f1_macro', 0.0):.3f}")
        print(f"  Success Rate: {mcq_metrics.get('success_rate', 0.0):.3f}")
        print(f"  Total Samples: {mcq_metrics.get('total_samples', 0)}")
        print(f"{'='*60}")

        return {
            "mcq_results": mcq_results,
            "mcq_metrics": mcq_metrics,
        }


def main():
    """Main function to run the evaluation."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Evaluate Retrieval Supervisor on CTI Bench dataset"
    )
    parser.add_argument(
        "--dataset-dir",
        default="cti_bench/datasets",
        help="Directory containing CTI Bench datasets",
    )
    parser.add_argument(
        "--output-dir",
        default="cti_bench/eval_output",
        help="Directory to save evaluation results",
    )
    parser.add_argument(
        "--kb-path",
        default="./cyber_knowledge_base",
        help="Path to cyber knowledge base",
    )
    parser.add_argument(
        "--llm-model", default="google_genai:gemini-2.0-flash", help="LLM model to use"
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        help="Maximum number of samples to evaluate (for testing)",
    )

    args = parser.parse_args()

    try:
        # Initialize supervisor
        print("Initializing Retrieval Supervisor...")
        supervisor = RetrievalSupervisor(
            llm_model=args.llm_model, kb_path=args.kb_path, max_iterations=3
        )

        # Initialize evaluator
        evaluator = CTIBenchEvaluator(
            supervisor=supervisor,
            dataset_dir=args.dataset_dir,
            output_dir=args.output_dir,
        )

        # Run evaluation
        results = evaluator.run_full_evaluation()

        print("Evaluation completed successfully!")

    except Exception as e:
        print(f"Evaluation failed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
