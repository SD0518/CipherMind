#!/usr/bin/env python3
"""
Compare performance metrics across different models.

Reads tactic_counts_summary.json and generates a comparison report
showing detection rates, coverage, accuracy, and effectiveness for each model.

Usage:
    python compare_models.py [--input INPUT_PATH] [--output OUTPUT_PATH]
"""
import argparse
import json
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
import statistics


class ModelComparator:
    """Compares performance metrics across different models"""

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
                }
            tactic_aggregates[tactic]["total_files"] += 1
            tactic_aggregates[tactic]["files_detected"] += item["tactic_detected"]
            tactic_aggregates[tactic]["total_events"] += item[
                "total_abnormal_events_detected"
            ]

        # Calculate detection rate
        total_files = sum(agg["total_files"] for agg in tactic_aggregates.values())
        total_detected = sum(
            agg["files_detected"] for agg in tactic_aggregates.values()
        )
        total_events = sum(agg["total_events"] for agg in tactic_aggregates.values())

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

        # Calculate accuracy
        accuracy_scores = []
        for tactic, agg in tactic_aggregates.items():
            if agg["total_files"] > 0:
                accuracy = agg["files_detected"] / agg["total_files"]
                accuracy_scores.append(accuracy)

        avg_accuracy = statistics.mean(accuracy_scores) if accuracy_scores else 0.0

        # Calculate effectiveness
        effectiveness_score = (
            detection_rate * 0.4 + coverage_percent * 0.3 + avg_accuracy * 100 * 0.3
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

        # Per-tactic breakdown
        per_tactic_detection = []
        for tactic, agg in sorted(tactic_aggregates.items()):
            files = agg["total_files"]
            detected = agg["files_detected"]
            events = agg["total_events"]

            tactic_detection_rate = (detected / files * 100) if files > 0 else 0.0

            per_tactic_detection.append(
                {
                    "tactic": tactic,
                    "total_files": files,
                    "files_detected": detected,
                    "files_missed": files - detected,
                    "total_abnormal_events_detected": events,
                    "detection_rate_percent": tactic_detection_rate,
                    "status": (
                        "GOOD"
                        if tactic_detection_rate >= 50
                        else ("POOR" if tactic_detection_rate > 0 else "NONE")
                    ),
                }
            )

        return {
            "model_name": model_data[0]["model"] if model_data else "unknown",
            "total_files_analyzed": total_files,
            "total_files_detected": total_detected,
            "total_files_missed": total_files - total_detected,
            "total_abnormal_events_detected": total_events,
            "total_tactics_tested": total_tactics,
            "detection_rate_percent": detection_rate,
            "coverage_percent": coverage_percent,
            "average_accuracy_score": avg_accuracy,
            "effectiveness_score": effectiveness_score,
            "grade": grade,
            "per_tactic_detection": per_tactic_detection,
            "tactics_with_detection": tactics_with_detection,
            "tactics_with_zero_detection": total_tactics - tactics_with_detection,
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
            "detection_rate_percent": 0.0,
            "coverage_percent": 0.0,
            "average_accuracy_score": 0.0,
            "effectiveness_score": 0.0,
            "grade": "CRITICAL",
            "per_tactic_detection": [],
            "tactics_with_detection": 0,
            "tactics_with_zero_detection": 0,
        }

    def generate_comparison(self) -> Dict[str, Any]:
        """Generate comprehensive model comparison report"""
        print("\n" + "=" * 80)
        print("GENERATING MODEL COMPARISON")
        print("=" * 80 + "\n")

        # Group data by model
        models_data = self.group_by_model()

        if not models_data:
            print("[WARNING] No model data found")
            return {"error": "No model data found"}

        print(f"Found {len(models_data)} models: {', '.join(models_data.keys())}")

        # Calculate metrics for each model
        model_metrics = {}
        for model_name, model_data in models_data.items():
            print(
                f"\nCalculating metrics for {model_name} ({len(model_data)} files)..."
            )
            model_metrics[model_name] = self.calculate_model_metrics(model_data)

        # Generate comparison summary
        comparison_summary = self._generate_comparison_summary(model_metrics)

        # Generate ranking
        ranking = self._generate_ranking(model_metrics)

        # Generate detailed comparison
        detailed_comparison = self._generate_detailed_comparison(model_metrics)

        report = {
            "timestamp": datetime.now().isoformat(),
            "total_models_compared": len(model_metrics),
            "models_analyzed": list(model_metrics.keys()),
            "comparison_summary": comparison_summary,
            "model_ranking": ranking,
            "detailed_model_metrics": model_metrics,
            "detailed_comparison": detailed_comparison,
        }

        return report

    def _generate_comparison_summary(
        self, model_metrics: Dict[str, Dict]
    ) -> Dict[str, Any]:
        """Generate high-level comparison summary"""
        if not model_metrics:
            return {}

        # Find best and worst performers
        best_detection = max(
            model_metrics.items(), key=lambda x: x[1]["detection_rate_percent"]
        )
        worst_detection = min(
            model_metrics.items(), key=lambda x: x[1]["detection_rate_percent"]
        )

        best_coverage = max(
            model_metrics.items(), key=lambda x: x[1]["coverage_percent"]
        )
        worst_coverage = min(
            model_metrics.items(), key=lambda x: x[1]["coverage_percent"]
        )

        best_effectiveness = max(
            model_metrics.items(), key=lambda x: x[1]["effectiveness_score"]
        )
        worst_effectiveness = min(
            model_metrics.items(), key=lambda x: x[1]["effectiveness_score"]
        )

        # Calculate averages
        avg_detection = statistics.mean(
            [m["detection_rate_percent"] for m in model_metrics.values()]
        )
        avg_coverage = statistics.mean(
            [m["coverage_percent"] for m in model_metrics.values()]
        )
        avg_effectiveness = statistics.mean(
            [m["effectiveness_score"] for m in model_metrics.values()]
        )

        return {
            "average_detection_rate_percent": avg_detection,
            "average_coverage_percent": avg_coverage,
            "average_effectiveness_score": avg_effectiveness,
            "best_detection": {
                "model": best_detection[0],
                "score": best_detection[1]["detection_rate_percent"],
            },
            "worst_detection": {
                "model": worst_detection[0],
                "score": worst_detection[1]["detection_rate_percent"],
            },
            "best_coverage": {
                "model": best_coverage[0],
                "score": best_coverage[1]["coverage_percent"],
            },
            "worst_coverage": {
                "model": worst_coverage[0],
                "score": worst_coverage[1]["coverage_percent"],
            },
            "best_overall": {
                "model": best_effectiveness[0],
                "score": best_effectiveness[1]["effectiveness_score"],
                "grade": best_effectiveness[1]["grade"],
            },
            "worst_overall": {
                "model": worst_effectiveness[0],
                "score": worst_effectiveness[1]["effectiveness_score"],
                "grade": worst_effectiveness[1]["grade"],
            },
        }

    def _generate_ranking(self, model_metrics: Dict[str, Dict]) -> List[Dict[str, Any]]:
        """Generate ranked list of models by effectiveness"""
        ranked_models = sorted(
            model_metrics.items(),
            key=lambda x: x[1]["effectiveness_score"],
            reverse=True,
        )

        ranking = []
        for rank, (model_name, metrics) in enumerate(ranked_models, 1):
            ranking.append(
                {
                    "rank": rank,
                    "model_name": model_name,
                    "effectiveness_score": metrics["effectiveness_score"],
                    "grade": metrics["grade"],
                    "detection_rate_percent": metrics["detection_rate_percent"],
                    "coverage_percent": metrics["coverage_percent"],
                    "average_accuracy_score": metrics["average_accuracy_score"],
                    "total_files_analyzed": metrics["total_files_analyzed"],
                }
            )

        return ranking

    def _generate_detailed_comparison(
        self, model_metrics: Dict[str, Dict]
    ) -> Dict[str, Any]:
        """Generate detailed side-by-side comparison"""
        if not model_metrics:
            return {}

        # Get all tactics across all models
        all_tactics = set()
        for metrics in model_metrics.values():
            for tactic_data in metrics["per_tactic_detection"]:
                all_tactics.add(tactic_data["tactic"])

        all_tactics = sorted(list(all_tactics))

        # Create tactic-by-tactic comparison
        tactic_comparison = {}
        for tactic in all_tactics:
            tactic_comparison[tactic] = {}
            for model_name, metrics in model_metrics.items():
                # Find this tactic in the model's data
                tactic_data = next(
                    (
                        t
                        for t in metrics["per_tactic_detection"]
                        if t["tactic"] == tactic
                    ),
                    None,
                )

                if tactic_data:
                    tactic_comparison[tactic][model_name] = {
                        "detection_rate_percent": tactic_data["detection_rate_percent"],
                        "files_detected": tactic_data["files_detected"],
                        "total_files": tactic_data["total_files"],
                        "status": tactic_data["status"],
                    }
                else:
                    tactic_comparison[tactic][model_name] = {
                        "detection_rate_percent": 0.0,
                        "files_detected": 0,
                        "total_files": 0,
                        "status": "NOT_TESTED",
                    }

        return {
            "tactic_by_tactic_comparison": tactic_comparison,
            "all_tactics_tested": all_tactics,
        }


def main():
    parser = argparse.ArgumentParser(
        description="Compare performance metrics across different models"
    )
    parser.add_argument(
        "--input",
        default="evaluation/full_pipeline/results/tactic_counts_summary.json",
        help="Path to tactic_counts_summary.json",
    )
    parser.add_argument(
        "--output",
        default="evaluation/full_pipeline/results/model_comparison.json",
        help="Output file for model comparison report",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}")
        print("Run count_tactics.py first to generate tactic counts")
        return 1

    # Run comparison
    comparator = ModelComparator(input_path)
    report = comparator.generate_comparison()

    # Save report
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # Display summary
    print("\n" + "=" * 80)
    print("MODEL COMPARISON COMPLETE")
    print("=" * 80)

    if "error" in report:
        print(f"Error: {report['error']}")
        return 1

    print(f"Models compared: {report['total_models_compared']}")
    print(f"Models: {', '.join(report['models_analyzed'])}")

    if report["model_ranking"]:
        print(
            f"\nTop performer: {report['model_ranking'][0]['model_name']} "
            f"(Score: {report['model_ranking'][0]['effectiveness_score']:.1f}, "
            f"Grade: {report['model_ranking'][0]['grade']})"
        )

    summary = report["comparison_summary"]
    if summary:
        print(f"\nAverage effectiveness: {summary['average_effectiveness_score']:.1f}")
        print(
            f"Best detection: {summary['best_detection']['model']} ({summary['best_detection']['score']:.1f}%)"
        )
        print(
            f"Best coverage: {summary['best_coverage']['model']} ({summary['best_coverage']['score']:.1f}%)"
        )

    print(f"\nReport saved to: {output_path}")
    print("=" * 80 + "\n")

    return 0


if __name__ == "__main__":
    exit(main())
