"""Cyber Assistant Pipeline

Combines the LLMMordorAnalyzer (log analysis agent) and MitreAgent (ATT&CK mapping & mitigation agent)
into a single workflow. The pipeline loads Mordor dataset logs, detects suspicious events with LLM, then
maps those events to MITRE ATT&CK techniques and suggested mitigations.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List

from agents.log_analysis_agent.log_analysis_agent import LLMMordorAnalyzer
from agents.mitre_retriever_agent.mitre_agent import MitreAgent
from utils.types import MitreAgentInput, SeverityLevel, AnalysisType


class CyberAssistantPipeline:
    """Unified workflow orchestrator for Log Analysis and MITRE Retriever agents."""

    def __init__(self, dataset_path: str | Path, llm_provider: str = "google") -> None:
        self.dataset_path = Path(dataset_path)
        self.llm_provider = llm_provider

        # Agents
        self.log_analyzer = LLMMordorAnalyzer(str(self.dataset_path), llm_provider=self.llm_provider)
        self.mitre_agent = MitreAgent(llm_provider=self.llm_provider)

    # ---------------------------------------------------------------------
    # Transformation utilities
    # ---------------------------------------------------------------------
    @staticmethod
    def _event_to_mitre_input(event: Dict[str, Any]) -> MitreAgentInput:
        """Convert a SuspiciousEvent (as dict) to MitreAgentInput dataclass."""
        # Map severity string to enum
        severity_str: str = str(event.get("severity", "low")).lower()
        severity_enum = {
            "low": SeverityLevel.LOW,
            "medium": SeverityLevel.MEDIUM,
            "high": SeverityLevel.HIGH,
            "critical": SeverityLevel.CRITICAL,
        }.get(severity_str, SeverityLevel.LOW)

        # Map analysis type string to enum
        analysis_type_str: str = str(event.get("analysis_type", "anomaly_detection")).lower()
        analysis_type_enum = {
            "anomaly_detection": AnalysisType.ANOMALY_DETECTION,
            "threat_hunting": AnalysisType.THREAT_HUNTING,
            "incident_response": AnalysisType.INCIDENT_RESPONSE,
            "compliance_check": AnalysisType.COMPLIANCE_CHECK,
        }.get(analysis_type_str, AnalysisType.ANOMALY_DETECTION)

        return MitreAgentInput(
            detected_anomalies=event.get("detected_anomalies", []),
            severity=severity_enum,
            confidence=float(event.get("confidence", 0.5)),

            analysis_type=analysis_type_enum,
            time_window=event.get("time_window", {}),
            affected_systems=event.get("affected_systems", []),

            indicators=event.get("indicators", {}),
            event_types=event.get("event_types", []),
            log_sources=event.get("log_sources", []),

            user_accounts=event.get("user_accounts", []),
            processes=event.get("processes", []),
            network_activity=event.get("network_activity", {}),
            file_operations=event.get("file_operations", {}),

            analysis_id=event.get("analysis_id", "UNKNOWN_ANALYSIS_ID"),
            timestamp=event.get("timestamp", ""),
            raw_summary=event.get("raw_summary", "")
        )

    # ------------------------------------------------------------------
    # Pipeline execution
    # ------------------------------------------------------------------
    async def run_async(self) -> Dict[str, Any]:
        """Execute the full pipeline asynchronously and return combined report."""
        print("[PIPELINE] Starting log analysis...")
        log_report = await self.log_analyzer.analyze()
        self.log_analyzer.print_summary(log_report)

        suspicious_events: List[Dict[str, Any]] = log_report.get("suspicious_events", [])
        mitre_results: List[Dict[str, Any]] = []

        if not suspicious_events:
            print("[PIPELINE] No suspicious events detected – skipping MITRE analysis.")
        else:
            print(f"[PIPELINE] Running MITRE analysis for {len(suspicious_events)} events...")
            for event in suspicious_events:
                mitre_input = self._event_to_mitre_input(event)
                result = self.mitre_agent.analyze_threat(mitre_input)
                mitre_results.append(result)

        combined_report = {
            "pipeline_timestamp": __import__("datetime").datetime.now().isoformat(),
            "dataset_analyzed": str(self.dataset_path),
            "log_analysis_report": log_report,
            "mitre_analysis_results": mitre_results,
        }
        return combined_report

    # ------------------------------------------------------------------
    def run(self, save_path: str | Path | None = None) -> Dict[str, Any]:
        """Sync wrapper that runs the async pipeline and optionally saves report to disk."""
        combined_report = asyncio.run(self.run_async())

        if save_path:
            save_path = Path(save_path)
            save_path.parent.mkdir(parents=True, exist_ok=True)
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(combined_report, f, indent=2)
            print(f"[PIPELINE] Combined report saved to {save_path}")

        # Print brief overview
        self._print_pipeline_summary(combined_report)
        return combined_report

    # ------------------------------------------------------------------
    @staticmethod
    def _print_pipeline_summary(report: Dict[str, Any]) -> None:
        """Print concise summary of pipeline results."""
        print("\n" + "=" * 100)
        print("CYBER ASSISTANT PIPELINE SUMMARY")
        print("=" * 100)

        log_overview = report["log_analysis_report"]["threat_overview"]
        print("[LOG ANALYSIS]")
        print(f"  • Total threats: {log_overview.get('total_threats', 0)}")
        print(f"  • Severity breakdown: {log_overview.get('severity_breakdown', {})}")

        mitre_count = len(report["mitre_analysis_results"])
        print("\n[MITRE ANALYSIS]")
        print(f"  • Total analyses performed: {mitre_count}")
        if mitre_count:
            first = report["mitre_analysis_results"][0]
            print(f"  • Techniques identified in first analysis: {first.get('techniques_found', len(first.get('technique_details', [])))}")

        print("=" * 100 + "\n")


# ----------------------------------------------------------------------
# Script execution helper
# ----------------------------------------------------------------------

def main():
    """CLI entrypoint for the pipeline."""
    import argparse

    parser = argparse.ArgumentParser(description="Run the Cyber Assistant multi-agent pipeline.")
    parser.add_argument("dataset", help="Path to directory containing Mordor JSONL logs")
    parser.add_argument("--output", "-o", help="Optional path to save the combined JSON report")
    parser.add_argument("--llm-provider", default="google", help="LLM provider to use (default: google)")
    args = parser.parse_args()

    pipeline = CyberAssistantPipeline(args.dataset, llm_provider=args.llm_provider)
    pipeline.run(save_path=args.output)


if __name__ == "__main__":
    main()
