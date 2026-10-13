from typing import List

from mitre_example_input import create_sample_log_input
from mitre_generator import MitreGenerator
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from utils.types import SeverityLevel, AnalysisType, MitreAgentInput


class MitreQueryGenerator:
    """Handles query generation and transformation for MITRE technique retrieval."""
    def __init__(self):
        self.tactic_mappings = {
            "process": "execution",
            "network": "command-and-control",
            "file": "persistence",
            "credential": "credential-access",
            "privilege": "privilege-escalation",
            "registry": "persistence",
            "service": "persistence",
            "scheduled": "persistence"
        }

    def generate_initial_queries(self, log_input: MitreAgentInput) -> List[str]:
        """Generate multiple targeted queries based on log analysis findings."""

        # Primary query based on main findings
        queries = [self.create_primary_query(log_input)]

        # Tactical queries based on specific indicators
        queries.extend(self.generate_indicator_queries(log_input))

        # Platform-specific queries
        queries.extend(self.generate_platform_queries(log_input))

        # Severity-based queries
        queries.extend(self.generate_severity_queries(log_input))

        # Analysis type specific queries
        queries.extend(self.generate_analysis_type_queries(log_input))

        return list(set(queries))  # Remove duplicates

    def create_primary_query(self, log_input: MitreAgentInput) -> str:
        """Create the main query based on log analysis findings."""
        key_terms = []

        for anomaly in log_input.detected_anomalies:
            if 'description' in anomaly:
                desc = anomaly['description'].lower()
                for term, tactic in self.tactic_mappings.items():
                    if term in desc:
                        key_terms.append(tactic)

        # Combine with event types
        all_terms = key_terms + log_input.event_types[:3]

        if all_terms:
            return ' '.join(all_terms[:5])
        else:
            return log_input.raw_summary[:100]

    @staticmethod
    def generate_indicator_queries(log_input: MitreAgentInput) -> List[str]:
        """Generate queries based on specific indicators."""
        queries = []

        if log_input.processes:
            for proc in log_input.processes[:3]:
                if 'powershell' in proc.lower():
                    queries.append("powershell script execution command injection")
                elif 'cmd' in proc.lower():
                    queries.append("command line execution shell commands")
                elif any(app in proc.lower() for app in ['winword', 'excel', 'pdf']):
                    queries.append("malicious document macro execution")
                else:
                    queries.append(f"process techniques {' '.join(log_input.processes[:3])}")

        if log_input.network_activity:
            queries.append("network reconnaissance data exfiltration command control")

        if log_input.file_operations:
            queries.append("file manipulation persistence backdoor installation")

        if log_input.user_accounts:
            queries.append("credential access privilege escalation lateral movement")

        return queries

    def generate_platform_queries(self, log_input: MitreAgentInput) -> List[str]:
        """Generate platform-specific queries."""
        queries = []
        platforms = self.infer_platforms(log_input)

        for platform in platforms:
            queries.append(f"{platform} persistence evasion techniques")

        return queries

    @staticmethod
    def generate_severity_queries(log_input: MitreAgentInput) -> List[str]:
        """Generate queries based on severity level."""
        queries = []

        if log_input.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
            queries.append("advanced persistent threat APT sophisticated attack")

        return queries

    def generate_analysis_type_queries(self, log_input: MitreAgentInput) -> List[str]:
        """Generate queries specific to analysis type."""
        queries = []

        if log_input.analysis_type == AnalysisType.INCIDENT_RESPONSE:
            queries.extend([
                "initial access entry vector",
                "impact data destruction encryption",
                "exfiltration data theft",
                "persistence backdoor implant"
            ])

        elif log_input.analysis_type == AnalysisType.THREAT_HUNTING:
            queries.extend([
                "defense evasion living off land",
                "persistence registry modification",
                "credential access memory dump",
                "lateral movement remote services"
            ])

        elif log_input.analysis_type == AnalysisType.ANOMALY_DETECTION:
            queries.extend([
                "execution unusual process",
                "command control beaconing",
                "collection automated",
                "discovery system information"
            ])

        return queries

    @staticmethod
    def infer_platforms(log_input: MitreAgentInput) -> List[str]:
        """Infer target platforms from log sources."""
        platforms = []

        for source in log_input.log_sources:
            if 'windows' in source.lower() or 'sysmon' in source.lower():
                platforms.append('Windows')
            elif 'linux' in source.lower() or 'syslog' in source.lower():
                platforms.append('Linux')
            elif 'macos' in source.lower():
                platforms.append('macOS')

        return list(set(platforms))

    def transform_query(self, original_query: str, context: MitreAgentInput) -> List[str]:
        """Transform queries for better retrieval using different strategies."""
        transformed_queries = [original_query]  # Keep original

        # Strategy 1: Add context-specific terms
        if context.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
            transformed_queries.append(f"{original_query} advanced persistent threat")

        # Strategy 2: Platform-specific transformation
        platforms = self.infer_platforms(context)
        for platform in platforms:
            transformed_queries.append(f"{platform} {original_query}")

        # Strategy 3: Tactic-focused transformation
        for term, tactic in self.tactic_mappings.items():
            if term in original_query.lower():
                transformed_queries.append(f"{tactic} {original_query}")

        # Strategy 4: Decomposition for complex queries
        if len(original_query.split()) > 5:
            words = original_query.split()
            mid = len(words) // 2
            transformed_queries.append(' '.join(words[:mid]))
            transformed_queries.append(' '.join(words[mid:]))

        return list(set(transformed_queries))

if __name__ == "__main__":
    log_input = create_sample_log_input()

    query_generator = MitreQueryGenerator()

    initial_queries = query_generator.generate_initial_queries(log_input)

    print("Initial Queries:")
    for q in initial_queries:
        print(f"- {q}")

    print("="*60)

    # Use these queries with the MitreGenerator
    agent = MitreGenerator(
        llm_provider="openai",
        model_name="gpt-4o",
        temperature=0.3,
        retriever_k=5,
        search_method="hybrid"
    )

    for i, query in enumerate(initial_queries, 1):
        print(f"\n{'=' * 80}")
        print(f"=== Test {i}: {query} ===")
        print('=' * 80)

        # Run analysis
        result = agent.generate(query)

        # Display results
        print(f"\n[RESULTS]")
        print(f"Confidence: {result['confidence']:.2f}")
        print(f"Techniques found: {result['retrieval_stats']['total_retrieved']}")
        print(f"Main techniques: {result['retrieval_stats']['main_techniques']}")
        print(f"Retrieval method: {result['retrieval_method']}")
        print(f"\nTop techniques: {', '.join(result['techniques_used'][:5])}")
        print(f"\nAnswer preview:")
        answer = result['analysis']
        print(answer)


