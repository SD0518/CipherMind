#!/usr/bin/env python3
"""
Evaluate system performance metrics.

Calculates detection rates, coverage, accuracy, and overall effectiveness
based on tactic occurrence counts. Generates separate reports for each model.

Usage:
    python evaluate_metrics.py [--input INPUT_PATH] [--output OUTPUT_PATH]
"""
import argparse
import json
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
import statistics


class SystemEvaluator:
    """Evaluates multi-agent system performance"""

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

    def calculate_detection_rate(self, model_data: List[Dict] = None) -> Dict[str, Any]:
        """Calculate detection rate: % of files where tactic was correctly detected"""
        data_to_use = model_data if model_data is not None else self.tactic_data

        # Aggregate by tactic
        tactic_aggregates = {}
        for item in data_to_use:
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

        total_files = sum(agg["total_files"] for agg in tactic_aggregates.values())
        total_detected = sum(
            agg["files_detected"] for agg in tactic_aggregates.values()
        )
        total_events = sum(agg["total_events"] for agg in tactic_aggregates.values())

        per_tactic_detection = []
        for tactic, agg in sorted(tactic_aggregates.items()):
            files = agg["total_files"]
            detected = agg["files_detected"]
            events = agg["total_events"]

            detection_rate = (detected / files * 100) if files > 0 else 0.0

            per_tactic_detection.append(
                {
                    "tactic": tactic,
                    "total_files": files,
                    "files_detected": detected,
                    "files_missed": files - detected,
                    "total_abnormal_events_detected": events,
                    "detection_rate_percent": detection_rate,
                    "status": (
                        "GOOD"
                        if detection_rate >= 50
                        else ("POOR" if detection_rate > 0 else "NONE")
                    ),
                }
            )

        overall_detection_rate = (
            (total_detected / total_files * 100) if total_files > 0 else 0.0
        )

        return {
            "overall_detection_rate_percent": overall_detection_rate,
            "total_files": total_files,
            "total_files_detected": total_detected,
            "total_files_missed": total_files - total_detected,
            "total_abnormal_events_detected": total_events,
            "total_tactics": len(tactic_aggregates),
            "per_tactic_detection": per_tactic_detection,
        }

    def calculate_coverage(self, model_data: List[Dict] = None) -> Dict[str, Any]:
        """Calculate coverage: how many tactics have at least one successful detection"""
        data_to_use = model_data if model_data is not None else self.tactic_data

        # Aggregate by tactic
        tactic_aggregates = {}
        for item in data_to_use:
            tactic = item["tactic"]
            if tactic not in tactic_aggregates:
                tactic_aggregates[tactic] = 0
            tactic_aggregates[tactic] += item["tactic_detected"]

        total_tactics = len(tactic_aggregates)
        tactics_with_detection = sum(
            1 for count in tactic_aggregates.values() if count > 0
        )
        tactics_with_zero_detection = total_tactics - tactics_with_detection

        coverage_percent = (
            (tactics_with_detection / total_tactics * 100) if total_tactics > 0 else 0.0
        )

        detected_tactics = sorted(
            [tactic for tactic, count in tactic_aggregates.items() if count > 0]
        )
        missed_tactics = sorted(
            [tactic for tactic, count in tactic_aggregates.items() if count == 0]
        )

        return {
            "coverage_percent": coverage_percent,
            "total_tactics_tested": total_tactics,
            "tactics_with_detection": tactics_with_detection,
            "tactics_with_zero_detection": tactics_with_zero_detection,
            "detected_tactics": detected_tactics,
            "missed_tactics": missed_tactics,
        }

    def calculate_accuracy_proxy(self, model_data: List[Dict] = None) -> Dict[str, Any]:
        """Calculate accuracy proxy: detection success rate per tactic"""
        data_to_use = model_data if model_data is not None else self.tactic_data

        # Aggregate by tactic
        tactic_aggregates = {}
        for item in data_to_use:
            tactic = item["tactic"]
            if tactic not in tactic_aggregates:
                tactic_aggregates[tactic] = {"total_files": 0, "files_detected": 0}
            tactic_aggregates[tactic]["total_files"] += 1
            tactic_aggregates[tactic]["files_detected"] += item["tactic_detected"]

        accuracy_scores = []
        for tactic, agg in sorted(tactic_aggregates.items()):
            if agg["total_files"] > 0:
                accuracy = agg["files_detected"] / agg["total_files"]
                accuracy_scores.append(
                    {
                        "tactic": tactic,
                        "accuracy_score": accuracy,
                        "interpretation": (
                            "Perfect"
                            if accuracy == 1.0
                            else ("Partial" if accuracy > 0 else "Failed")
                        ),
                    }
                )

        avg_accuracy = (
            statistics.mean([s["accuracy_score"] for s in accuracy_scores])
            if accuracy_scores
            else 0.0
        )

        return {
            "average_accuracy_score": avg_accuracy,
            "per_tactic_accuracy": accuracy_scores,
            "perfect_matches": sum(
                1 for s in accuracy_scores if s["accuracy_score"] == 1.0
            ),
            "partial_matches": sum(
                1 for s in accuracy_scores if 0 < s["accuracy_score"] < 1.0
            ),
            "failed_matches": sum(
                1 for s in accuracy_scores if s["accuracy_score"] == 0.0
            ),
        }

    def calculate_effectiveness(self, model_data: List[Dict] = None) -> Dict[str, Any]:
        """Calculate overall system effectiveness score (0-100)"""
        detection = self.calculate_detection_rate(model_data)
        coverage = self.calculate_coverage(model_data)
        accuracy = self.calculate_accuracy_proxy(model_data)

        # Weighted effectiveness score
        # 40% detection rate, 30% coverage, 30% accuracy
        effectiveness_score = (
            detection["overall_detection_rate_percent"] * 0.4
            + coverage["coverage_percent"] * 0.3
            + accuracy["average_accuracy_score"] * 100 * 0.3
        )

        # Grade the system
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
            "effectiveness_score": effectiveness_score,
            "grade": grade,
            "component_scores": {
                "detection_rate": detection["overall_detection_rate_percent"],
                "coverage_rate": coverage["coverage_percent"],
                "accuracy_score": accuracy["average_accuracy_score"] * 100,
            },
        }

    def identify_issues(self, model_data: List[Dict] = None) -> List[str]:
        """Identify specific issues and gaps"""
        issues = []

        detection = self.calculate_detection_rate(model_data)
        coverage = self.calculate_coverage(model_data)

        # Check overall detection
        if detection["overall_detection_rate_percent"] < 20:
            issues.append(
                f"CRITICAL: Overall detection rate is only {detection['overall_detection_rate_percent']:.1f}%. "
                f"System is failing to detect most attacks ({detection['total_files_missed']}/{detection['total_files']} files missed)."
            )
        elif detection["overall_detection_rate_percent"] < 50:
            issues.append(
                f"WARNING: Detection rate is {detection['overall_detection_rate_percent']:.1f}%, "
                f"below acceptable threshold of 50% ({detection['total_files_missed']}/{detection['total_files']} files missed)."
            )

        # Check coverage
        if coverage["tactics_with_zero_detection"] > 0:
            missed = ", ".join(coverage["missed_tactics"])
            issues.append(
                f"COVERAGE GAP: {coverage['tactics_with_zero_detection']} tactics have zero detection: {missed}"
            )

        # Check for specific problematic tactics
        for item in detection["per_tactic_detection"]:
            if item["total_files"] > 0 and item["detection_rate_percent"] == 0:
                issues.append(
                    f"TACTIC FAILURE: '{item['tactic']}' - "
                    f"{item['total_files']} files analyzed, 0 detected"
                )

        # Check for data quality issues
        data_to_use = model_data if model_data is not None else self.tactic_data
        zero_event_tactics = [
            item["tactic"]
            for item in data_to_use
            if item["total_abnormal_events_detected"] == 0
        ]
        if zero_event_tactics:
            unique_zero = list(set(zero_event_tactics))
            issues.append(
                f"DATA ISSUE: No events to analyze for tactics: {', '.join(unique_zero)}"
            )

        if not issues:
            issues.append(
                "No critical issues detected. System is performing within acceptable parameters."
            )

        return issues

    def run_evaluation_for_model(
        self, model_name: str, model_data: List[Dict]
    ) -> Dict[str, Any]:
        """Run full evaluation for a specific model"""
        print(f"\nEvaluating model: {model_name} ({len(model_data)} files)")

        detection = self.calculate_detection_rate(model_data)
        coverage = self.calculate_coverage(model_data)
        accuracy = self.calculate_accuracy_proxy(model_data)
        effectiveness = self.calculate_effectiveness(model_data)
        issues = self.identify_issues(model_data)

        report = {
            "timestamp": datetime.now().isoformat(),
            "model_name": model_name,
            "evaluation_metrics": {
                "detection_rate": detection,
                "coverage": coverage,
                "accuracy_proxy": accuracy,
                "effectiveness": effectiveness,
            },
            "issues_identified": issues,
        }

        return report

    def run_evaluation(self) -> Dict[str, Any]:
        """Run full evaluation and compile report for all models"""
        print("\n" + "=" * 80)
        print("RUNNING SYSTEM EVALUATION")
        print("=" * 80 + "\n")

        # Group data by model
        models_data = self.group_by_model()

        if not models_data:
            print("[WARNING] No model data found")
            return {"error": "No model data found"}

        print(f"Found {len(models_data)} models: {', '.join(models_data.keys())}")

        # Generate reports for each model
        model_reports = {}
        for model_name, model_data in models_data.items():
            print(f"\nProcessing model: {model_name}")
            model_reports[model_name] = self.run_evaluation_for_model(
                model_name, model_data
            )

        # Create summary report
        summary_report = {
            "timestamp": datetime.now().isoformat(),
            "total_models_evaluated": len(model_reports),
            "models": list(model_reports.keys()),
            "model_reports": model_reports,
        }

        return summary_report


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate multi-agent system performance"
    )
    parser.add_argument(
        "--input",
        default="evaluation/full_pipeline/results/tactic_counts_summary.json",
        help="Path to tactic_counts_summary.json",
    )
    parser.add_argument(
        "--output",
        default="evaluation/full_pipeline/results/evaluation_report.json",
        help="Output file for evaluation report",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}")
        print("Run count_tactics.py first to generate tactic counts")
        return 1

    # Run evaluation
    evaluator = SystemEvaluator(input_path)
    report = evaluator.run_evaluation()

    if "error" in report:
        print(f"[ERROR] {report['error']}")
        return 1

    # Save main report
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # Save individual model reports
    for model_name, model_report in report["model_reports"].items():
        model_output_path = (
            output_path.parent
            / f"evaluation_report_{model_name.replace(':', '_').replace('/', '_')}.json"
        )
        model_output_path.write_text(
            json.dumps(model_report, indent=2), encoding="utf-8"
        )
        print(f"Model report saved: {model_output_path}")

    # Display summary
    print("\n" + "=" * 80)
    print("EVALUATION COMPLETE")
    print("=" * 80)
    print(f"Models evaluated: {report['total_models_evaluated']}")
    print(f"Models: {', '.join(report['models'])}")

    # Show summary for each model
    for model_name, model_report in report["model_reports"].items():
        effectiveness = model_report["evaluation_metrics"]["effectiveness"]
        print(f"\n{model_name}:")
        print(f"  Effectiveness Score: {effectiveness['effectiveness_score']:.1f}/100")
        print(f"  Grade: {effectiveness['grade']}")
        print(
            f"  Detection Rate: {effectiveness['component_scores']['detection_rate']:.1f}%"
        )
        print(f"  Coverage: {effectiveness['component_scores']['coverage_rate']:.1f}%")
        print(f"  Accuracy: {effectiveness['component_scores']['accuracy_score']:.1f}%")

    print(f"\nMain report saved to: {output_path}")
    print("=" * 80 + "\n")

    return 0


if __name__ == "__main__":
    exit(main())
