from typing import List, Dict, Any
import pandas as pd
import json
import os
from datetime import datetime
import numpy as np

# Import the required classes from your project
from mitre_agent import MitreAgent
from utils.types import MitreAgentInput, AnalysisType, SeverityLevel

class MitreRetrievalEvaluator:
    """Evaluation harness for MITRE retrieval performance with recall@K and other IR metrics."""

    def __init__(self, results_dir: str = "./evaluation_results"):
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)

    def calculate_recall_at_k(self,
                              retrieved_techniques: List[str],
                              relevant_techniques: List[str],
                              k: int) -> float:
        """Calculate recall@K for retrieval evaluation."""
        if not relevant_techniques:
            return 0.0

        retrieved_k = set(retrieved_techniques[:k])
        relevant_set = set(relevant_techniques)

        return len(retrieved_k & relevant_set) / len(relevant_set)

    def calculate_precision_at_k(self,
                                 retrieved_techniques: List[str],
                                 relevant_techniques: List[str],
                                 k: int) -> float:
        """Calculate precision@K for retrieval evaluation."""
        if k == 0:
            return 0.0

        retrieved_k = set(retrieved_techniques[:k])
        relevant_set = set(relevant_techniques)

        return len(retrieved_k & relevant_set) / k

    def calculate_ndcg_at_k(self,
                            retrieved_techniques: List[str],
                            relevant_techniques: List[str],
                            k: int) -> float:
        """Calculate NDCG@K for retrieval evaluation."""
        def dcg_at_k(relevance_scores: List[int], k: int) -> float:
            scores = relevance_scores[:k]
            return sum(rel / np.log2(i + 2) for i, rel in enumerate(scores))

        # Create relevance scores (1 if relevant, 0 if not)
        relevance_scores = [1 if tech in relevant_techniques else 0
                            for tech in retrieved_techniques[:k]]

        # Calculate DCG
        dcg = dcg_at_k(relevance_scores, k)

        # Calculate IDCG (ideal DCG)
        ideal_relevance = [1] * min(len(relevant_techniques), k) + [0] * max(0, k - len(relevant_techniques))
        idcg = dcg_at_k(ideal_relevance, k)

        return dcg / idcg if idcg > 0 else 0.0

    def analyze_retrieval_gaps(self, test_cases: List[Dict[str, Any]], agent: MitreAgent) -> Dict[str, Any]:
        """Analyze what techniques are being retrieved vs expected to identify gaps."""
        gap_analysis = {
            'missed_techniques': {},
            'unexpected_techniques': {},
            'retrieval_patterns': {},
            'test_case_analysis': []
        }

        for i, test_case in enumerate(test_cases, 1):
            log_input = self._create_agent_input(test_case, i)
            analysis_result = agent.analyze_threat(log_input)

            retrieved_ids = [t['attack_id'] for t in analysis_result.get('technique_details', [])]
            expected_ids = test_case.get('expected_techniques', [])

            missed = set(expected_ids) - set(retrieved_ids)
            unexpected = set(retrieved_ids) - set(expected_ids)

            # Track missed techniques globally
            for tech_id in missed:
                if tech_id not in gap_analysis['missed_techniques']:
                    gap_analysis['missed_techniques'][tech_id] = 0
                gap_analysis['missed_techniques'][tech_id] += 1

            # Track unexpected techniques
            for tech_id in unexpected:
                if tech_id not in gap_analysis['unexpected_techniques']:
                    gap_analysis['unexpected_techniques'][tech_id] = 0
                gap_analysis['unexpected_techniques'][tech_id] += 1

            test_analysis = {
                'test_case': i,
                'query': test_case['query'],
                'expected': expected_ids,
                'retrieved': retrieved_ids[:10],  # Top 10 for readability
                'missed': list(missed),
                'found': list(set(expected_ids) & set(retrieved_ids)),
                'coverage': len(set(expected_ids) & set(retrieved_ids)) / len(expected_ids) if expected_ids else 0
            }
            gap_analysis['test_case_analysis'].append(test_analysis)

            print(f"\nTest Case {i}: {test_case['category']}")
            print(f"  Query: {test_case['query']}")
            print(f"  Expected: {expected_ids}")
            print(f"  Retrieved (top 5): {retrieved_ids[:5]}")
            print(f"  Found: {list(set(expected_ids) & set(retrieved_ids))}")
            print(f"  Missed: {list(missed)}")
            print(f"  Coverage: {test_analysis['coverage']:.2f}")

        return gap_analysis

    def evaluate_retrieval_performance(self,
                                       test_cases: List[Dict[str, Any]],
                                       agent: MitreAgent,
                                       k_values=None,
                                       run_name: str = None) -> Dict[str, Any]:
        """Evaluate retrieval performance across multiple test cases."""

        if k_values is None:
            k_values = [1, 3, 5, 10]
        if not run_name:
            run_name = f"retrieval_eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        print(f"[INFO] Running retrieval evaluation: {run_name}")

        results = {
            'run_name': run_name,
            'timestamp': datetime.now().isoformat(),
            'test_cases_count': len(test_cases),
            'k_values': k_values,
            'detailed_results': [],
            'aggregated_metrics': {}
        }

        all_recalls = {k: [] for k in k_values}
        all_precisions = {k: [] for k in k_values}
        all_ndcgs = {k: [] for k in k_values}

        for i, test_case in enumerate(test_cases, 1):
            print(f"[INFO] Evaluating test case {i}/{len(test_cases)}: {test_case.get('category', 'unknown')}")

            # Create agent input
            log_input = self._create_agent_input(test_case, i)

            # Get agent analysis
            analysis_result = agent.analyze_threat(log_input)

            # Extract retrieved techniques (before and after refinement)
            initial_techniques = [t['attack_id'] for t in analysis_result.get('technique_details', [])]
            refined_techniques = analysis_result.get('techniques_used', [])

            # Get expected techniques
            expected_techniques = test_case.get('expected_techniques', [])

            # Calculate metrics for different k values
            test_result = {
                'test_case_id': i,
                'category': test_case.get('category', 'unknown'),
                'query': test_case['query'],
                'expected_techniques': expected_techniques,
                'initial_retrieved': initial_techniques,
                'refined_retrieved': refined_techniques,
                'refinement_applied': analysis_result.get('refinement_applied', False),
                'metrics': {}
            }

            for k in k_values:
                # Evaluate both initial and refined retrieval
                initial_recall = self.calculate_recall_at_k(initial_techniques, expected_techniques, k)
                initial_precision = self.calculate_precision_at_k(initial_techniques, expected_techniques, k)
                initial_ndcg = self.calculate_ndcg_at_k(initial_techniques, expected_techniques, k)

                refined_recall = self.calculate_recall_at_k(refined_techniques, expected_techniques, k)
                refined_precision = self.calculate_precision_at_k(refined_techniques, expected_techniques, k)
                refined_ndcg = self.calculate_ndcg_at_k(refined_techniques, expected_techniques, k)

                test_result['metrics'][f'initial_recall@{k}'] = initial_recall
                test_result['metrics'][f'initial_precision@{k}'] = initial_precision
                test_result['metrics'][f'initial_ndcg@{k}'] = initial_ndcg

                test_result['metrics'][f'refined_recall@{k}'] = refined_recall
                test_result['metrics'][f'refined_precision@{k}'] = refined_precision
                test_result['metrics'][f'refined_ndcg@{k}'] = refined_ndcg

                # Collect for aggregation (use refined results)
                all_recalls[k].append(refined_recall)
                all_precisions[k].append(refined_precision)
                all_ndcgs[k].append(refined_ndcg)

            results['detailed_results'].append(test_result)

            print(f"  Expected: {len(expected_techniques)} techniques")
            print(f"  Retrieved (refined): {len(refined_techniques)} techniques")
            print(f"  Recall@5: {test_result['metrics'].get('refined_recall@5', 0):.3f}")

        # Calculate aggregated metrics
        for k in k_values:
            results['aggregated_metrics'][f'avg_recall@{k}'] = np.mean(all_recalls[k])
            results['aggregated_metrics'][f'avg_precision@{k}'] = np.mean(all_precisions[k])
            results['aggregated_metrics'][f'avg_ndcg@{k}'] = np.mean(all_ndcgs[k])
            results['aggregated_metrics'][f'std_recall@{k}'] = np.std(all_recalls[k])

        # Calculate overall metrics
        results['summary'] = self._create_retrieval_summary(results)

        # Save results
        self._save_evaluation_results(results)

        return results

    def _create_agent_input(self, test_case: Dict[str, Any], test_id: int) -> MitreAgentInput:
        """Create MitreAgentInput from test case."""
        return MitreAgentInput(
            analysis_id=f"eval_test_{test_id}",
            raw_summary=test_case['query'],
            detected_anomalies=[{
                'id': f'anom_{test_id}',
                'description': test_case['query'],
                'timestamp': datetime.now().isoformat(),
                'confidence': 0.8
            }],
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            analysis_type=AnalysisType.INCIDENT_RESPONSE,
            time_window={
                "start": datetime.now().replace(hour=14, minute=0).isoformat(),
                "end": datetime.now().replace(hour=15, minute=0).isoformat()
            },
            affected_systems=['test-system'],
            indicators={
                "ips": ["192.168.1.100"],
                "domains": ["test-domain.com"],
                "file_hashes": ["test_hash"]
            },
            event_types=test_case.get('event_types', ['process_creation']),
            log_sources=test_case.get('log_sources', ['Windows']),
            user_accounts=["test_user"],
            processes=test_case.get('processes', []),
            network_activity={
                "external_connections": 1,
                "unusual_ports": [4444],
                "data_transfer_gb": 0.5
            },
            file_operations={
                "created_files": 1,
                "modified_files": 1,
                "deleted_files": 0
            },
            timestamp=datetime.now().isoformat()
        )

    def _create_retrieval_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary of retrieval evaluation."""
        metrics = results['aggregated_metrics']

        # Find best performing k value for recall
        best_recall_k = max(results['k_values'],
                            key=lambda k: metrics.get(f'avg_recall@{k}', 0))

        return {
            'test_cases_evaluated': results['test_cases_count'],
            'best_recall_k': best_recall_k,
            'best_recall_score': metrics.get(f'avg_recall@{best_recall_k}', 0),
            'recall_at_5': metrics.get('avg_recall@5', 0),
            'precision_at_5': metrics.get('avg_precision@5', 0),
            'ndcg_at_5': metrics.get('avg_ndcg@5', 0),
            'refinement_impact': self._calculate_refinement_impact(results)
        }

    def _calculate_refinement_impact(self, results: Dict[str, Any]) -> Dict[str, float]:
        """Calculate the impact of refinement on retrieval performance."""
        improvements = []

        for test_result in results['detailed_results']:
            if test_result.get('refinement_applied', False):
                initial_recall = test_result['metrics'].get('initial_recall@5', 0)
                refined_recall = test_result['metrics'].get('refined_recall@5', 0)
                improvement = refined_recall - initial_recall
                improvements.append(improvement)

        return {
            'avg_recall_improvement': np.mean(improvements) if improvements else 0.0,
            'cases_with_refinement': len(improvements),
            'positive_improvements': len([x for x in improvements if x > 0])
        }

    def _save_evaluation_results(self, results: Dict[str, Any]):
        """Save evaluation results to files."""
        # Save detailed results as JSON
        results_file = os.path.join(self.results_dir, f"{results['run_name']}_retrieval.json")
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        # Save summary to CSV
        summary_file = os.path.join(self.results_dir, "retrieval_summary.csv")

        summary_row = {
            'run_name': results['run_name'],
            'timestamp': results['timestamp'],
            'test_cases': results['test_cases_count'],
            **results['aggregated_metrics'],
            **results['summary']
        }

        df = pd.DataFrame([summary_row])

        if os.path.exists(summary_file):
            df.to_csv(summary_file, mode='a', header=False, index=False)
        else:
            df.to_csv(summary_file, index=False)

    def diagnose_refinement_issues(self, test_cases: List[Dict[str, Any]], agent: MitreAgent) -> Dict[str, Any]:
        """Diagnose why refinement is degrading performance."""

        refinement_diagnosis = {
            'query_quality_issues': [],
            'retrieval_method_conflicts': [],
            'ranking_degradation': [],
            'detailed_analysis': []
        }

        for i, test_case in enumerate(test_cases, 1):
            log_input = self._create_agent_input(test_case, i)

            # Get step-by-step analysis to see where degradation occurs
            print(f"\n=== DIAGNOSTIC TEST CASE {i} ===")
            print(f"Query: {test_case['query']}")
            print(f"Expected: {test_case.get('expected_techniques', [])}")

            # Step 1: Initial retrieval
            initial_queries = agent.query_generator.generate_initial_queries(log_input)
            print(f"Initial queries: {initial_queries}")

            initial_techniques = []
            for query in initial_queries:
                techs = agent._retrieve_techniques(query, "hybrid", k=6)
                initial_techniques.extend([t['attack_id'] for t in techs])

            initial_unique = list(set(initial_techniques))
            print(f"Initial techniques found: {initial_unique[:10]}")

            # Step 2: Full analysis (with refinement)
            analysis_result = agent.analyze_threat(log_input)
            final_techniques = [t['attack_id'] for t in analysis_result.get('technique_details', [])]

            print(f"Final techniques: {final_techniques[:10]}")
            print(f"Refinement applied: {analysis_result.get('refinement_applied', False)}")

            if analysis_result.get('refinement_applied', False):
                additional_queries = analysis_result.get('additional_queries_used', [])
                print(f"Additional queries: {additional_queries}")

                # Check if additional queries are relevant
                for query in additional_queries:
                    print(f"  Testing refinement query: '{query}'")
                    refined_techs = agent._retrieve_techniques(query, "hybrid", k=6)
                    refined_ids = [t['attack_id'] for t in refined_techs]
                    print(f"    Retrieved: {refined_ids[:5]}")

                    # Check overlap with expected
                    expected = set(test_case.get('expected_techniques', []))
                    overlap = set(refined_ids) & expected
                    print(f"    Relevant hits: {list(overlap)}")

            # Calculate metrics for diagnosis
            expected = set(test_case.get('expected_techniques', []))
            initial_relevant = set(initial_unique) & expected
            final_relevant = set(final_techniques) & expected

            diagnosis = {
                'test_case': i,
                'initial_recall': len(initial_relevant) / len(expected) if expected else 0,
                'final_recall': len(final_relevant) / len(expected) if expected else 0,
                'refinement_delta': (len(final_relevant) - len(initial_relevant)) / len(expected) if expected else 0,
                'initial_relevant': list(initial_relevant),
                'final_relevant': list(final_relevant),
                'lost_techniques': list(initial_relevant - final_relevant),
                'gained_techniques': list(final_relevant - initial_relevant)
            }

            refinement_diagnosis['detailed_analysis'].append(diagnosis)

            print(f"Initial recall: {diagnosis['initial_recall']:.3f}")
            print(f"Final recall: {diagnosis['final_recall']:.3f}")
            print(f"Delta: {diagnosis['refinement_delta']:+.3f}")

            if diagnosis['lost_techniques']:
                print(f"LOST relevant techniques: {diagnosis['lost_techniques']}")
            if diagnosis['gained_techniques']:
                print(f"GAINED relevant techniques: {diagnosis['gained_techniques']}")

        return refinement_diagnosis

def create_mitre_retrieval_test_cases() -> List[Dict[str, Any]]:
    """Create test cases specifically for retrieval evaluation."""
    return [
        {
            'query': 'PowerShell process injection with network communication',
            'expected_techniques': ['T1055', 'T1059.001'],
            'category': 'process_injection',
            'processes': ['powershell.exe'],
            'event_types': ['process_creation', 'network_connection']
        },
        {
            'query': 'Registry modification for persistence using scheduled tasks',
            'expected_techniques': ['T1547.001', 'T1053'],
            'category': 'persistence',
            'event_types': ['registry_modification', 'scheduled_task_creation']
        },
        {
            'query': 'LSASS memory dumping for credential access',
            'expected_techniques': ['T1003.001', 'T1555', 'T1547.008'],
            'category': 'credential_access',
            'processes': ['lsass.exe'],
            'event_types': ['process_access']
        },
        {
            'query': 'Encrypted C2 communication over HTTPS',
            'expected_techniques': ['T1071.001', 'T1041'],
            'category': 'command_control',
            'event_types': ['network_connection']
        },
        {
            'query': 'DLL injection for privilege escalation and defense evasion',
            'expected_techniques': ['T1055.001', 'T1548.002', 'T1068', 'T1211'],
            'category': 'privilege_escalation',
            'event_types': ['process_creation', 'dll_load']
        }
    ]

if __name__ == "__main__":
    print("Starting MITRE Retrieval Evaluation...")
    print("=" * 60)

    # Initialize evaluator
    evaluator = MitreRetrievalEvaluator()

    # Create test cases
    test_cases = create_mitre_retrieval_test_cases()

    # Initialize agent
    agent = MitreAgent(
        llm_provider="openai",
        model_name="gpt-4o",
        max_iterations=2
    )

    # Run retrieval evaluation
    evaluation_result = evaluator.evaluate_retrieval_performance(
        test_cases=test_cases,
        agent=agent,
        k_values=[1, 3, 5, 10, 15],
        run_name="mitre_retrieval_baseline"
    )

    # Print results
    print(f"\n{'=' * 60}")
    print("RETRIEVAL EVALUATION SUMMARY")
    print(f"{'=' * 60}")

    summary = evaluation_result['summary']
    print(f"Test Cases: {summary['test_cases_evaluated']}")
    print(f"Best Recall@K: {summary['best_recall_score']:.3f} at K={summary['best_recall_k']}")
    print(f"Recall@5: {summary['recall_at_5']:.3f}")
    print(f"Precision@5: {summary['precision_at_5']:.3f}")
    print(f"NDCG@5: {summary['ndcg_at_5']:.3f}")


    print(f"\nDetailed metrics by K:")
    for k in evaluation_result['k_values']:
        recall = evaluation_result['aggregated_metrics'][f'avg_recall@{k}']
        precision = evaluation_result['aggregated_metrics'][f'avg_precision@{k}']
        ndcg = evaluation_result['aggregated_metrics'][f'avg_ndcg@{k}']
        print(f"  K={k:2d}: Recall={recall:.3f}, Precision={precision:.3f}, NDCG={ndcg:.3f}")

    # print(f"\n{'=' * 60}")
    # print("GAP ANALYSIS")
    # print(f"{'=' * 60}")
    #
    # gap_analysis = evaluator.analyze_retrieval_gaps(test_cases, agent)
    #
    # print(f"\nMost Frequently Missed Techniques:")
    # missed_sorted = sorted(gap_analysis['missed_techniques'].items(),
    #                        key=lambda x: x[1], reverse=True)
    # for tech_id, count in missed_sorted[:10]:
    #     print(f"  {tech_id}: missed in {count}/{len(test_cases)} test cases")
    #
    # print(f"\nMost Frequently Retrieved (but unexpected):")
    # unexpected_sorted = sorted(gap_analysis['unexpected_techniques'].items(),
    #                            key=lambda x: x[1], reverse=True)
    # for tech_id, count in unexpected_sorted[:10]:
    #     print(f"  {tech_id}: appeared in {count}/{len(test_cases)} test cases")

    diagnosis = evaluator.diagnose_refinement_issues(test_cases, agent)
    print(f"\n{'=' * 60}")
    print("REFINEMENT DIAGNOSIS")
    print(f"{'=' * 60}")

    for detail in diagnosis['detailed_analysis']:
        print(f"\nTest Case {detail['test_case']}:")
        print(f"  Initial Recall: {detail['initial_recall']:.3f}")
        print(f"  Final Recall:   {detail['final_recall']:.3f}")
        print(f"  Delta:         {detail['refinement_delta']:+.3f}")
        if detail['lost_techniques']:
            print(f"  LOST: {detail['lost_techniques']}")
        if detail['gained_techniques']:
            print(f"  GAINED: {detail['gained_techniques']}")
