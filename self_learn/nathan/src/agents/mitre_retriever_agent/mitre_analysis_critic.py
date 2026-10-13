from mitre_query_generator import MitreQueryGenerator
from typing import List, Dict, Any
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from utils.types import MitreAgentInput, AnalysisType

class MitreAnalysisCritic:
    """Handles self-critique and analysis refinement."""
    def __init__(self, query_generator: MitreQueryGenerator):
        self.query_generator = query_generator
        self.coverage_threshold = 0.8
        self.tactic_weights = {
            'execution': 2.0,
            'privilege-escalation': 2.0,
            'initial-access': 1.5,
            'persistence': 1.5,
            'command-and-control': 1.0,
            'exfiltration': 1.0,
            'impact': 1.8
        }

    def iterative_critique_analysis(self, log_input: MitreAgentInput, techniques: List[Dict], analysis: Dict, max_iterations: int = 3, retriever=None) -> Dict[str, Any]:
        """Iterative critique with looping until coverage threshold is met."""
        if retriever is None:
            raise ValueError("Retriever instance required for iterative analysis")

        iteration = 0
        current_techniques = techniques
        all_additional_queries = []
        seen_technique_ids = {tech['attack_id'] for tech in current_techniques}

        while iteration < max_iterations:
            critique = self.critique_analysis(log_input, current_techniques, analysis)

            print(f"[DEBUG] Iteration {iteration + 1}: Coverage score {critique['coverage_score']:.2f}")

            if critique['coverage_score'] >= self.coverage_threshold:
                print(f"[INFO] Coverage threshold {self.coverage_threshold} reached")
                break

            if not critique['needs_refinement']:
                break

            # Collect additional queries for this iteration
            additional_queries = critique['additional_queries']
            all_additional_queries.extend(additional_queries)

            new_techniques = []
            for query in additional_queries:
                query_results = retriever.hybrid_search(query, k=5)
                # Filter out already seen techniques
                for tech in query_results:
                    if tech['attack_id'] not in seen_technique_ids:
                        new_techniques.append(tech)
                        seen_technique_ids.add(tech['attack_id'])

            if new_techniques:
                current_techniques.extend(new_techniques)
                print(f"[DEBUG] Added {len(new_techniques)} new techniques in iteration {iteration + 1}")
            else:
                print(f"[DEBUG] No new techniques found in iteration {iteration + 1}")
                break

            iteration += 1

        return {
            "final_critique": critique,
            "final_techniques": current_techniques,
            "iterations_performed": iteration,
            "all_additional_queries": all_additional_queries,
            "coverage_achieved": critique['coverage_score'] >= self.coverage_threshold,
            "total_techniques": len(current_techniques)
        }

    def critique_analysis(self, log_input: MitreAgentInput, techniques: List[Dict], analysis: Dict) -> Dict[str, Any]:
        """Critique with weighted coverage scoring."""
        gaps = []
        additional_queries = []

        # Check for missing attack phases with priority
        gaps_found, tactics_queries = self._check_weighted_tactic_coverage(log_input, techniques)
        gaps.extend(gaps_found)
        additional_queries.extend(tactics_queries)

        # Check for platform coverage
        platform_gaps, platform_queries = self._check_platform_coverage(log_input, techniques)
        gaps.extend(platform_gaps)
        additional_queries.extend(platform_queries)

        # Check for indicator-specific techniques
        indicator_gaps, indicator_queries = self._check_indicator_coverage(log_input, techniques)
        gaps.extend(indicator_gaps)
        additional_queries.extend(indicator_queries)

        # Calculate dynamic k recommendation
        dynamic_k = self._calculate_dynamic_k(log_input, techniques)

        return {
            "needs_refinement": len(gaps) > 0,
            "identified_gaps": gaps,
            "additional_queries": additional_queries[:3],
            "coverage_score": self._calculate_weighted_coverage_score(log_input, techniques),
            "recommended_k": dynamic_k,
            "gap_priority": self._prioritize_gaps(gaps)
        }

    def _check_weighted_tactic_coverage(self, log_input: MitreAgentInput, techniques: List[Dict]) -> tuple[List[str], List[str]]:
        """Check tactic coverage with weighting based on anomaly types."""
        gaps = []
        queries = []

        tactics_found = set()
        for tech in techniques:
            tactics_found.update(tech.get('tactics', []))

        # Expected tactics based on anomaly analysis
        expected_tactics = self._determine_priority_tactics(log_input)
        missing_tactics = set(expected_tactics) - tactics_found

        if missing_tactics:
            # Prioritize missing tactics by weight
            weighted_missing = sorted(missing_tactics,
                                      key=lambda t: self.tactic_weights.get(t, 1.0),
                                      reverse=True)
            gaps.append(f"Missing high-priority tactics: {', '.join(weighted_missing[:3])}")

            for tactic in weighted_missing[:2]:  # Focus on top 2
                queries.append(f"{tactic} techniques")

        return gaps, queries

    def _determine_priority_tactics(self, log_input: MitreAgentInput) -> List[str]:
        """Determine priority tactics based on anomaly analysis."""
        priority_tactics = set()

        # Analyze anomaly descriptions for tactic hints
        for anomaly in log_input.detected_anomalies:
            desc = anomaly.get('description', '').lower()

            if any(term in desc for term in ['process', 'execution', 'spawn']):
                priority_tactics.update(['execution', 'privilege-escalation'])
            if any(term in desc for term in ['network', 'connection', 'ip']):
                priority_tactics.update(['command-and-control', 'exfiltration'])
            if any(term in desc for term in ['file', 'registry', 'service']):
                priority_tactics.add('persistence')

        # Add default tactics based on analysis type
        default_tactics = {
            AnalysisType.INCIDENT_RESPONSE: ['initial-access', 'execution', 'impact'],
            AnalysisType.THREAT_HUNTING: ['persistence', 'defense-evasion'],
            AnalysisType.ANOMALY_DETECTION: ['execution', 'command-and-control']
        }

        priority_tactics.update(default_tactics.get(log_input.analysis_type, []))

        return list(priority_tactics)

    def _check_indicator_coverage(self, log_input: MitreAgentInput, techniques: List[Dict]) -> tuple[List[str], List[str]]:
        """Check indicator coverage checking with specific process/network analysis."""
        gaps = []
        queries = []

        tactics_found = set()
        for tech in techniques:
            tactics_found.update(tech.get('tactics', []))

        # Process-based analysis
        if log_input.processes:
            suspicious_processes = ['powershell.exe', 'cmd.exe', 'rundll32.exe']
            if any(proc in log_input.processes for proc in suspicious_processes):
                if 'execution' not in tactics_found:
                    gaps.append("Suspicious process execution but no execution techniques found")
                    queries.append("process injection execution techniques")

        # Network analysis
        if log_input.network_activity:
            unusual_ports = log_input.network_activity.get('unusual_ports', [])
            if unusual_ports and 'command-and-control' not in tactics_found:
                gaps.append(f"Unusual ports {unusual_ports} but no C2 techniques found")
                queries.append("command and control unusual ports communication")

        return gaps, queries

    def _check_platform_coverage(self, log_input: MitreAgentInput, techniques: List[Dict]) -> tuple[List[str], List[str]]:
        """Check if all relevant platforms are covered."""
        gaps = []
        queries = []

        log_platforms = self.query_generator.infer_platforms(log_input)
        covered_platforms = set()

        for tech in techniques:
            covered_platforms.update(tech.get('platforms', []))

        missing_platforms = set(log_platforms) - covered_platforms
        if missing_platforms:
            gaps.append(f"Missing platform coverage: {', '.join(missing_platforms)}")
            for platform in missing_platforms:
                queries.append(f"{platform} specific attack techniques")

        return gaps, queries

    def _calculate_weighted_coverage_score(self, log_input: MitreAgentInput, techniques: List[Dict]) -> float:
        """Calculate weighted coverage score prioritizing important tactics."""
        expected_tactics = self._determine_priority_tactics(log_input)
        if not expected_tactics:
            return 1.0

        tactics_found = set()
        for tech in techniques:
            tactics_found.update(tech.get('tactics', []))

        # Calculate weighted score
        total_weight = sum(self.tactic_weights.get(tactic, 1.0) for tactic in expected_tactics)
        covered_weight = sum(self.tactic_weights.get(tactic, 1.0)
                             for tactic in expected_tactics if tactic in tactics_found)

        return covered_weight / total_weight if total_weight > 0 else 1.0

    def _calculate_dynamic_k(self, log_input: MitreAgentInput, techniques: List[Dict]) -> int:
        """Calculate dynamic k value based on coverage and complexity."""
        base_k = 6

        coverage_score = self._calculate_weighted_coverage_score(log_input, techniques)

        if coverage_score < 0.4:
            return 20  # Aggressive retrieval for low coverage
        elif coverage_score < 0.6:
            return 12  # Moderate increase
        else:
            return base_k  # Sufficient coverage

    def _prioritize_gaps(self, gaps: List[str]) -> Dict[str, float]:
        """Assign priority scores to identified gaps."""
        priorities = {}

        for gap in gaps:
            if 'execution' in gap.lower():
                priorities[gap] = 2.0
            elif 'privilege' in gap.lower():
                priorities[gap] = 2.0
            elif 'network' in gap.lower() or 'c2' in gap.lower():
                priorities[gap] = 1.5
            else:
                priorities[gap] = 1.0

        return priorities