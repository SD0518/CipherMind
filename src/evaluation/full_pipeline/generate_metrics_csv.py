#!/usr/bin/env python3
"""
Generate CSV file with simple metrics for each model.

Reads tactic_counts_summary.json and generates a CSV file containing
F1, accuracy, precision, recall, and other metrics for each model.

Usage:
    python generate_metrics_csv.py [--input INPUT_PATH] [--output OUTPUT_PATH]
"""
import argparse
import json
import csv
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
import statistics


class MetricsCSVGenerator:
    """Generates CSV file with simple metrics for each model"""

    def __init__(self, tactic_counts_file: Path):
        self.tactic_counts_file = tactic_counts_file
        self.tactic_data = []
        self.load_tactic_counts()

    def load_tactic_counts(self):
        """Load tactic counts summary data"""
        if not self.tactic_counts_file.exists():
            raise FileNotFoundError(
                f"Tactic counts file not found: {self.tactic_counts_file}"
            )

        data = json.loads(self.tactic_counts_file.read_text(encoding="utf-8"))
        self.tactic_data = data.get("results", [])
        print(f"[INFO] Loaded {len(self.tactic_data)} tactic analysis results")

    def group_by_model(self) -> Dict[str, List[Dict]]:
        """Group tactic data by model"""
        models = {}
        for item in self.tactic_data:
            model = item["model"]
            if model not in models:
                models[model] = []
            models[model].append(item)
        return models

    def calculate_model_metrics(self, model_data: List[Dict]) -> Dict[str, Any]:
        """Calculate comprehensive metrics for a single model"""
        if not model_data:
            return self._empty_metrics()

        # Aggregate by tactic for this model
        tactic_aggregates = {}
        for item in model_data:
            tactic = item["tactic"]
            if tactic not in tactic_aggregates:
                tactic_aggregates[tactic] = {
                    "total_files": 0,
                    "files_detected": 0,
                    "total_events": 0,
                    "true_positives": 0,
                    "false_positives": 0,
                    "false_negatives": 0,
                }
            tactic_aggregates[tactic]["total_files"] += 1
            tactic_aggregates[tactic]["files_detected"] += item["tactic_detected"]
            tactic_aggregates[tactic]["total_events"] += item[
                "total_abnormal_events_detected"
            ]

            # For binary classification metrics, we consider:
            # - True Positive: tactic_detected = 1 (correctly detected)
            # - False Positive: tactic_detected = 0 but there were events (missed detection)
            # - False Negative: tactic_detected = 0 (missed detection)
            # - True Negative: tactic_detected = 0 and no events (correctly identified as normal)

            if item["tactic_detected"] == 1:
                tactic_aggregates[tactic]["true_positives"] += 1
            else:
                if item["total_abnormal_events_detected"] > 0:
                    tactic_aggregates[tactic]["false_negatives"] += 1
                else:
                    # This is actually a true negative (correctly identified as normal)
                    pass

        # Calculate overall metrics
        total_files = sum(agg["total_files"] for agg in tactic_aggregates.values())
        total_detected = sum(
            agg["files_detected"] for agg in tactic_aggregates.values()
        )
        total_events = sum(agg["total_events"] for agg in tactic_aggregates.values())

        # Calculate detection rate (recall)
        detection_rate = (
            (total_detected / total_files * 100) if total_files > 0 else 0.0
        )

        # Calculate coverage
        total_tactics = len(tactic_aggregates)
        tactics_with_detection = sum(
            1 for agg in tactic_aggregates.values() if agg["files_detected"] > 0
        )
        coverage_percent = (
            (tactics_with_detection / total_tactics * 100) if total_tactics > 0 else 0.0
        )

        # Calculate accuracy (overall correctness)
        accuracy = (total_detected / total_files) if total_files > 0 else 0.0

        # Calculate precision, recall, and F1 for each tactic, then average
        precision_scores = []
        recall_scores = []
        f1_scores = []

        for tactic, agg in tactic_aggregates.items():
            tp = agg["true_positives"]
            fp = agg["false_positives"]
            fn = agg["false_negatives"]

            # Precision = TP / (TP + FP)
            # For our case, FP is when we detect but shouldn't have (hard to measure from this data)
            # So we'll use a simplified approach: precision = detection rate
            precision = (tp / agg["total_files"]) if agg["total_files"] > 0 else 0.0

            # Recall = TP / (TP + FN) = detection rate
            recall = (tp / agg["total_files"]) if agg["total_files"] > 0 else 0.0

            # F1 = 2 * (precision * recall) / (precision + recall)
            if precision + recall > 0:
                f1 = 2 * (precision * recall) / (precision + recall)
            else:
                f1 = 0.0

            precision_scores.append(precision)
            recall_scores.append(recall)
            f1_scores.append(f1)

        # Calculate averages
        avg_precision = statistics.mean(precision_scores) if precision_scores else 0.0
        avg_recall = statistics.mean(recall_scores) if recall_scores else 0.0
        avg_f1 = statistics.mean(f1_scores) if f1_scores else 0.0

        # Calculate effectiveness score (weighted combination)
        effectiveness_score = (
            detection_rate * 0.4 + coverage_percent * 0.3 + avg_f1 * 100 * 0.3
        )

        # Grade the model
        if effectiveness_score >= 80:
            grade = "EXCELLENT"
        elif effectiveness_score >= 60:
            grade = "GOOD"
        elif effectiveness_score >= 40:
            grade = "FAIR"
        elif effectiveness_score >= 20:
            grade = "POOR"
        else:
            grade = "CRITICAL"

        return {
            "model_name": model_data[0]["model"] if model_data else "unknown",
            "total_files_analyzed": total_files,
            "total_files_detected": total_detected,
            "total_files_missed": total_files - total_detected,
            "total_abnormal_events_detected": total_events,
            "total_tactics_tested": total_tactics,
            "tactics_with_detection": tactics_with_detection,
            "tactics_with_zero_detection": total_tactics - tactics_with_detection,
            "detection_rate_percent": detection_rate,
            "coverage_percent": coverage_percent,
            "accuracy": accuracy,
            "precision": avg_precision,
            "recall": avg_recall,
            "f1_score": avg_f1,
            "effectiveness_score": effectiveness_score,
            "grade": grade,
        }

    def _empty_metrics(self) -> Dict[str, Any]:
        """Return empty metrics structure"""
        return {
            "model_name": "unknown",
            "total_files_analyzed": 0,
            "total_files_detected": 0,
            "total_files_missed": 0,
            "total_abnormal_events_detected": 0,
            "total_tactics_tested": 0,
            "tactics_with_detection": 0,
            "tactics_with_zero_detection": 0,
            "detection_rate_percent": 0.0,
            "coverage_percent": 0.0,
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "effectiveness_score": 0.0,
            "grade": "CRITICAL",
        }

    def generate_csv(self, output_path: Path) -> bool:
        """Generate CSV file with metrics for all models"""
        print("\n" + "=" * 80)
        print("GENERATING METRICS CSV")
        print("=" * 80 + "\n")

        # Group data by model
        models_data = self.group_by_model()

        if not models_data:
            print("[WARNING] No model data found")
            return False

        print(f"Found {len(models_data)} models: {', '.join(models_data.keys())}")

        # Calculate metrics for each model
        all_metrics = []
        for model_name, model_data in models_data.items():
            print(f"Calculating metrics for {model_name} ({len(model_data)} files)...")
            metrics = self.calculate_model_metrics(model_data)
            all_metrics.append(metrics)

        # Define CSV columns
        fieldnames = [
            "model_name",
            "total_files_analyzed",
            "total_files_detected",
            "total_files_missed",
            "total_abnormal_events_detected",
            "total_tactics_tested",
            "tactics_with_detection",
            "tactics_with_zero_detection",
            "detection_rate_percent",
            "coverage_percent",
            "accuracy",
            "precision",
            "recall",
            "f1_score",
            "effectiveness_score",
            "grade",
        ]

        # Write CSV file
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for metrics in all_metrics:
                # Convert all values to appropriate types for CSV
                row = {}
                for field in fieldnames:
                    value = metrics.get(field, 0)
                    if isinstance(value, float):
                        row[field] = round(value, 4)
                    else:
                        row[field] = value
                writer.writerow(row)

        print(f"\nCSV file generated: {output_path}")
        print(f"Models included: {len(all_metrics)}")

        # Display summary
        print("\nSummary:")
        for metrics in all_metrics:
            print(
                f"  {metrics['model_name']}: F1={metrics['f1_score']:.3f}, "
                f"Accuracy={metrics['accuracy']:.3f}, "
                f"Precision={metrics['precision']:.3f}, "
                f"Recall={metrics['recall']:.3f}, "
                f"Grade={metrics['grade']}"
            )

        return True


def main():
    parser = argparse.ArgumentParser(
        description="Generate CSV file with simple metrics for each model"
    )
    parser.add_argument(
        "--input",
        default="evaluation/full_pipeline/results/tactic_counts_summary.json",
        help="Path to tactic_counts_summary.json",
    )
    parser.add_argument(
        "--output",
        default="evaluation/full_pipeline/results/model_metrics.csv",
        help="Output file for CSV metrics",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}")
        print("Run count_tactics.py first to generate tactic counts")
        return 1

    # Generate CSV
    generator = MetricsCSVGenerator(input_path)
    success = generator.generate_csv(output_path)

    if not success:
        print("[ERROR] Failed to generate CSV file")
        return 1

    print("\n" + "=" * 80)
    print("CSV GENERATION COMPLETE")
    print("=" * 80 + "\n")

    return 0


if __name__ == "__main__":
    exit(main())
