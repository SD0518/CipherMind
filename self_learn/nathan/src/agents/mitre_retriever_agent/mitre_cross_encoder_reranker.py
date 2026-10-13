from typing import List, Dict
from sentence_transformers import CrossEncoder

from utils.types import MitreAgentInput


class MitreCrossEncoderReranker:
    """Cross-encoder reranking for final technique selection."""

    def __init__(self):
        try:
            # Load cross-encoder model
            self.cross_encoder = CrossEncoder('cross-encoder/ms-marco-MiniLM-L12-v2')
            print("[INFO] Cross-encoder reranker initialized")
        except Exception as e:
            print(f"[WARNING] Failed to load cross-encoder: {e}")
            self.cross_encoder = None

    def rerank_techniques(self, query: str, techniques: List[Dict], top_k: int = 10, log_input: MitreAgentInput = None) -> List[Dict]:
        """Context-aware reranking that preserves domain expertise."""

        if not self.cross_encoder or len(techniques) <= top_k:
            return techniques[:top_k]

        try:
            incident_context = self._build_incident_context(log_input) if log_input else query

            pairs = []
            for tech in techniques:
                tech_text = f"{tech.get('name', '')} {tech.get('description', '')}"
                pairs.append([incident_context, tech_text])

            scores = self.cross_encoder.predict(pairs)

            for i, tech in enumerate(techniques):
                cross_score = float(scores[i])
                relevance_score = tech.get('relevance_score', 0)

                # Preserve domain expertise with confidence weighting
                domain_confidence = self._calculate_domain_confidence(tech)

                if domain_confidence > 0.8:  # High domain confidence
                    tech['final_score'] = relevance_score * 0.9 + cross_score * 0.1
                elif domain_confidence > 0.5:  # Medium domain confidence
                    tech['final_score'] = relevance_score * 0.7 + cross_score * 0.3
                else:  # Low domain confidence - let cross-encoder decide
                    tech['final_score'] = relevance_score * 0.3 + cross_score * 0.7

            return sorted(techniques, key=lambda x: x['final_score'], reverse=True)[:top_k]

        except Exception as e:
            print(f"[WARNING] Cross-encoder reranking failed: {e}")
            return techniques[:top_k]

    def _build_incident_context(self, log_input: MitreAgentInput) -> str:
        """Build rich incident context for better semantic matching."""
        context_parts = []

        # Attack indicators
        if log_input.detected_anomalies:
            anomaly_desc = " ".join([a.get('description', '') for a in log_input.detected_anomalies[:3]])
            context_parts.append(anomaly_desc)

        # Technical indicators
        if log_input.processes:
            context_parts.append(f"processes: {' '.join(log_input.processes[:3])}")

        if log_input.event_types:
            context_parts.append(f"events: {' '.join(log_input.event_types[:3])}")

        return " ".join(context_parts)

    def _calculate_domain_confidence(self, tech: Dict) -> float:
        """Calculate confidence in domain-specific ranking."""
        confidence = 0.0

        # High confidence if technique was top in priority area
        if hasattr(tech, 'area_rank') and tech.area_rank <= 2:
            confidence += 0.5

        # High confidence if technique matches multiple evidence types
        evidence_matches = len(tech.get('evidence_matches', []))
        confidence += min(evidence_matches * 0.2, 0.4)

        # High confidence if found by multiple queries
        query_frequency = len(set(tech.get('found_by_queries', [])))
        confidence += min(query_frequency * 0.1, 0.3)

        return min(confidence, 1.0)