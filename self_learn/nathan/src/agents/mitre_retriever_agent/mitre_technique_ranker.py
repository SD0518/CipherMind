from typing import List, Dict, Any
from utils.types import MitreAgentInput, AnalysisType, SeverityLevel
from sentence_transformers import SentenceTransformer
import numpy as np

import transformers
transformers.logging.set_verbosity_error()
class MitreTechniqueRanker:
    """Handles ranking and scoring of retrieved MITRE techniques."""
    def __init__(self):
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        self.tactic_weights = {
            'execution': 1.5,
            'privilege-escalation': 1.5,
            'initial-access': 1.2,
            'persistence': 1.2,
            'command-and-control': 1.0,
            'exfiltration': 1.0,
            'impact': 1.4,
            'defense-evasion': 1.3
        }

    def rank_techniques_by_relevance(self, techniques: Dict[str, Any], log_input: MitreAgentInput) -> List[Dict[str, Any]]:
        """Ranking with evidence proximity and sub-technique collapsing."""
        # Calculate scores
        scored_techniques = []
        for tech_id, tech in techniques.items():
            score = self.calculate_relevance_score(tech, log_input)
            tech['relevance_score'] = score
            tech['evidence_matches'] = self._find_evidence_matches(tech, log_input)
            scored_techniques.append(tech)

        # Sort by score
        scored_techniques.sort(key=lambda x: x['relevance_score'], reverse=True)

        # Collapse sub-techniques
        collapsed_techniques = self._collapse_sub_techniques(scored_techniques)

        return collapsed_techniques

    def calculate_relevance_score(self, tech: Dict[str, Any], log_input: MitreAgentInput) -> float:
        """Scoring with evidence proximity and tactic weighting."""
        score = 0

        # Base score: query frequency
        score += len(set(tech.get('found_by_queries', []))) * 2

        # Evidence proximity boost
        evidence_score = self._calculate_evidence_proximity(tech, log_input)
        score += evidence_score * 5  # Major boost for evidence matching

        # Weighted tactic relevance
        tactics = tech.get('tactics', [])
        for tactic in tactics:
            weight = self.tactic_weights.get(tactic, 1.0)
            score += weight

        # Platform match bonus
        log_platforms = self._infer_platforms(log_input)
        tech_platforms = tech.get('platforms', [])
        platform_overlap = len(set(log_platforms) & set(tech_platforms))
        score += platform_overlap * 2

        # Anomaly-specific boosting
        score += self._calculate_anomaly_specific_boost(tech, log_input)

        # Severity and analysis type bonus
        score += self._calculate_context_bonus(tech, log_input)

        return score

    def _calculate_evidence_proximity(self, tech: Dict[str, Any], log_input: MitreAgentInput) -> float:
        """Calculate semantic similarity between technique and anomalies."""
        try:
            tech_description = tech.get('description', tech.get('name', ''))

            # Combine all anomaly descriptions with weights
            weighted_anomalies = []
            for anomaly in log_input.detected_anomalies:
                desc = anomaly.get('description', '')
                weighted_anomalies.append(desc)

            if not weighted_anomalies or not tech_description:
                return 0.0

            # Calculate embedding similarity
            tech_emb = self.embedding_model.encode([tech_description])
            anomaly_emb = self.embedding_model.encode(weighted_anomalies)

            similarities = []
            for anomaly_vec in anomaly_emb:
                similarity = np.dot(tech_emb[0], anomaly_vec) / (
                        np.linalg.norm(tech_emb[0]) * np.linalg.norm(anomaly_vec)
                )
                similarities.append(similarity)

            max_similarity = max(similarities) if similarities else 0.0

            return float(max_similarity * 3.0)
        except Exception as e:
            print(f"[WARNING] Error calculating evidence proximity: {e}")
            return 0.0

    def _calculate_anomaly_specific_boost(self, tech: Dict[str, Any], log_input: MitreAgentInput) -> float:
        """Boost techniques based on specific anomaly indicators."""
        boost = 0.0
        tech_name = tech.get('name', '').lower()
        tech_desc = tech.get('description', '').lower()
        tech_content = f"{tech_name} {tech_desc}"

        # Process-based anomalies
        for process in log_input.processes:
            if process.lower() in tech_content:
                boost += 3.0

        # Network-based anomalies
        if log_input.network_activity:
            if any(term in tech_content for term in ['network', 'protocol', 'communication']):
                boost += 2.0

        # File-based anomalies
        if log_input.file_operations:
            if any(term in tech_content for term in ['file', 'document', 'execution']):
                boost += 2.0

        return boost

    def _collapse_sub_techniques(self, techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Collapse sub-techniques, keeping only the highest-scoring variant."""
        # Group by main technique ID
        technique_groups = {}
        for tech in techniques:
            attack_id = tech['attack_id']
            main_id = attack_id.split('.')[0]  # T1055.001 -> T1055

            if main_id not in technique_groups:
                technique_groups[main_id] = []
            technique_groups[main_id].append(tech)

        collapsed = []
        for main_id, group in technique_groups.items():
            if len(group) == 1:
                collapsed.append(group[0])
            else:
                # Prefer more specific sub-techniques if they have higher scores
                # Otherwise keep the main technique
                main_tech = next((t for t in group if '.' not in t['attack_id']), None)
                sub_techs = [t for t in group if '.' in t['attack_id']]

                if sub_techs and main_tech:
                    best_sub = max(sub_techs, key=lambda x: x['relevance_score'])
                    if best_sub['relevance_score'] > main_tech['relevance_score']:
                        # Sub-technique better
                        best_sub['collapsed_main'] = main_tech['attack_id']
                        collapsed.append(best_sub)
                    else:
                        # Keep main technique
                        main_tech['collapsed_variants'] = [t['attack_id'] for t in sub_techs]
                        collapsed.append(main_tech)
                else:
                    # Keep highest scoring
                    best_tech = max(group, key=lambda x: x['relevance_score'])
                    best_tech['collapsed_variants'] = [t['attack_id'] for t in group if t != best_tech]
                    collapsed.append(best_tech)

        return collapsed

    def _find_evidence_matches(self, tech: Dict[str, Any], log_input: MitreAgentInput) -> List[str]:
        """Find specific evidence snippets that match this technique."""
        matches = []
        tech_content = f"{tech.get('name', '')} {tech.get('description', '')}".lower()

        for anomaly in log_input.detected_anomalies:
            desc = anomaly.get('description', '')
            # Simple keyword matching
            if any(process.lower() in tech_content for process in log_input.processes):
                matches.append(f"Process evidence: {desc}")
            if log_input.network_activity and 'network' in tech_content:
                matches.append(f"Network evidence: {desc}")

        return matches

    def _calculate_context_bonus(self, tech: Dict[str, Any], log_input: MitreAgentInput) -> float:
        """Calculate bonus based on severity and analysis type."""
        bonus = 0.0

        # Severity bonus for main techniques
        if log_input.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
            if not tech.get('is_subtechnique', False):
                bonus += 1.0

        # Analysis type specific bonuses
        tactics = tech.get('tactics', [])
        if log_input.analysis_type == AnalysisType.INCIDENT_RESPONSE:
            if any(tactic in ['impact', 'exfiltration', 'command-and-control'] for tactic in tactics):
                bonus += 1.5
        elif log_input.analysis_type == AnalysisType.THREAT_HUNTING:
            if any(tactic in ['persistence', 'defense-evasion', 'privilege-escalation'] for tactic in tactics):
                bonus += 1.5

        return bonus

    def _infer_platforms(self, log_input: MitreAgentInput) -> List[str]:
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
