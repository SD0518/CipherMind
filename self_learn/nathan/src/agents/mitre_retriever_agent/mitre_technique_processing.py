from typing import List, Dict, Any
from mitre_technique_ranker import MitreTechniqueRanker
from utils.types import MitreAgentInput

class MitreTechniqueProcessor:
    """Handles processing and enrichment of retrieved techniques."""

    def __init__(self, ranker: MitreTechniqueRanker):
        self.ranker = ranker

    def process_retrieved_techniques(self, techniques_by_query: Dict[str, List[Dict]], log_input: MitreAgentInput) -> Dict[str, Any]:
        """Process and consolidate techniques from multiple queries."""
        all_techniques = {}

        # Consolidate techniques with provenance tracking
        for query, techniques in techniques_by_query.items():
            for tech in techniques:
                tech_id = tech['attack_id']
                if tech_id not in all_techniques:
                    all_techniques[tech_id] = tech
                    all_techniques[tech_id]['found_by_queries'] = []

                all_techniques[tech_id]['found_by_queries'].append(query)

        # Rank by relevance
        ranked_techniques = self.ranker.rank_techniques_by_relevance(all_techniques, log_input)

        return {
            "all_techniques": all_techniques,
            "ranked_techniques": ranked_techniques,
            "total_unique_techniques": len(all_techniques)
        }

if __name__ == "__main__":
    from mitre_technique_ranker import MitreTechniqueRanker
    from mitre_example_input import create_sample_log_input

    print("Testing MitreTechniqueProcessor...")
    print("="*60)

    # Initialize components
    ranker = MitreTechniqueRanker()
    processor = MitreTechniqueProcessor(ranker)

    # Create test data
    sample_input = create_sample_log_input()

    # Mock techniques from different queries
    mock_techniques_by_query = {
        'process execution injection': [
            {
                'attack_id': 'T1055',
                'name': 'Process Injection',
                'tactics': ['execution', 'privilege-escalation'],
                'platforms': ['Windows', 'Linux'],
                'is_subtechnique': False,
                'mitigation_count': 3
            },
            {
                'attack_id': 'T1055.001',
                'name': 'Dynamic-link Library Injection',
                'tactics': ['execution'],
                'platforms': ['Windows'],
                'is_subtechnique': True,
                'mitigation_count': 2
            }
        ],
        'network communication command control': [
            {
                'attack_id': 'T1071',
                'name': 'Application Layer Protocol',
                'tactics': ['command-and-control'],
                'platforms': ['Windows', 'Linux', 'macOS'],
                'is_subtechnique': False,
                'mitigation_count': 4
            },
            {
                'attack_id': 'T1055',  # Duplicate
                'name': 'Process Injection',
                'tactics': ['execution', 'privilege-escalation'],
                'platforms': ['Windows', 'Linux'],
                'is_subtechnique': False,
                'mitigation_count': 3
            }
        ],
        'persistence registry service': [
            {
                'attack_id': 'T1547',
                'name': 'Boot or Logon Autostart Execution',
                'tactics': ['persistence', 'privilege-escalation'],
                'platforms': ['Windows', 'Linux', 'macOS'],
                'is_subtechnique': False,
                'mitigation_count': 5
            }
        ]
    }

    print(f"Testing with {len(mock_techniques_by_query)} query groups:")
    for query, techniques in mock_techniques_by_query.items():
        print(f"- '{query}': {len(techniques)} techniques")

    # Test processing
    print(f"\n" + "="*40)
    print("Testing technique processing...")

    processed_results = processor.process_retrieved_techniques(mock_techniques_by_query, sample_input)

    print(f"\nProcessing Results:")
    print(f"- Total unique techniques: {processed_results['total_unique_techniques']}")
    print(f"- Ranked techniques: {len(processed_results['ranked_techniques'])}")

    # Show consolidated techniques with provenance
    print(f"\nConsolidated techniques:")
    for tech_id, tech in processed_results['all_techniques'].items():
        found_by = tech.get('found_by_queries', [])
        print(f"- {tech_id}: {tech['name']} (found by {len(found_by)} queries)")
        for query in found_by:
            print(f"  * {query}")

    # Show top ranked techniques
    print(f"\nTop 5 ranked techniques:")
    for i, tech in enumerate(processed_results['ranked_techniques'][:5], 1):
        score = tech.get('relevance_score', 0)
        print(f"{i}. {tech['attack_id']}: {tech['name']} (score: {score:.2f})")

    # Test with empty input
    print(f"\n" + "="*30)
    print("Testing with empty techniques...")

    empty_results = processor.process_retrieved_techniques({}, sample_input)
    print(f"Empty processing results: {empty_results['total_unique_techniques']} techniques")

    # Test with single query
    print(f"\n" + "="*30)
    print("Testing with single query...")

    single_query = {'test_query': [mock_techniques_by_query['process execution injection'][0]]}
    single_results = processor.process_retrieved_techniques(single_query, sample_input)

    print(f"Single query results:")
    print(f"- Unique techniques: {single_results['total_unique_techniques']}")
    print(f"- Top technique: {single_results['ranked_techniques'][0]['attack_id']}")