from datetime import datetime
from mitre_retriever import MitreRetriever
from mitre_generator import MitreGenerator
from mitre_analysis_critic import MitreAnalysisCritic
from mitre_planner import MitreAnalysisPlanner
from mitre_query_generator import MitreQueryGenerator
from mitre_technique_processing import MitreTechniqueProcessor
from mitre_technique_ranker import MitreTechniqueRanker
from mitre_cross_encoder_reranker import MitreCrossEncoderReranker
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from utils.types import MitreAgentInput
from typing import Dict, Any

class MitreAgent:
    def __init__(self, llm_provider: str = "google", model_name: str = "gemini-2.0-flash", max_iterations: int = 3):

        self.retriever = MitreRetriever()
        self.generator = MitreGenerator(llm_provider=llm_provider, model_name=model_name)

        self.query_generator = MitreQueryGenerator()
        self.ranker = MitreTechniqueRanker()
        self.critic = MitreAnalysisCritic(self.query_generator)
        self.planner = MitreAnalysisPlanner(self.query_generator)
        self.processor = MitreTechniqueProcessor(self.ranker)
        self.cross_encoder = MitreCrossEncoderReranker()

        self.max_iterations = max_iterations

    def analyze_threat(self, log_input: MitreAgentInput) -> Dict[str, Any]:
        """Analysis pipeline with iterative refinement."""
        print(f"[INFO] Starting threat analysis for {log_input.analysis_id}")

        # Step 1: Create analysis plan
        plan = self.planner.create_analysis_plan(log_input)
        print(f"[DEBUG] Analysis plan created with strategy: {plan['search_strategy']}")

        # Step 2: Execute planned analysis with dynamic k
        analysis_results = self._execute_analysis_plan(log_input, plan)

        # Step 3: Iterative critique and refinement
        final_analysis = self._iterative_critique_and_refine(log_input, analysis_results)

        return final_analysis

    def _execute_analysis_plan(self, log_input: MitreAgentInput, plan: Dict) -> Dict[str, Any]:
        """Execute analysis with dynamic k and reduced duplicate queries."""
        print(f"[INFO] Executing analysis pipeline")

        # Generate initial queries
        initial_queries = self.query_generator.generate_initial_queries(log_input)
        print(f"[DEBUG] Generated {len(initial_queries)} initial queries")

        # Execute planned analysis
        planned_results = self.planner.execute_planned_queries(log_input, plan, self.retriever)

        # Combine results
        all_query_results = {}
        search_method = plan["search_strategy"]

        # Execute initial queries once
        for query in initial_queries:
            techniques = self._retrieve_techniques(query, search_method, k=8)  # Start with base k
            all_query_results[f"initial_{query}"] = techniques

        # Add planned results
        for area, result in planned_results.items():
            all_query_results[area] = result['techniques']

        # Process and rank all techniques
        processed_results = self.processor.process_retrieved_techniques(all_query_results, log_input)

        # Add metadata
        processed_results.update({
            "plan": plan,
            "planned_results": planned_results,
            "reasoning_trace": self.planner.generate_reasoning_trace(log_input, plan, planned_results),
            "search_method_used": search_method,
            "initial_query_count": len(initial_queries)
        })

        return processed_results

    def _iterative_critique_and_refine(self, log_input: MitreAgentInput, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Iterative critique with dynamic k adjustment."""
        print(f"[INFO] Starting iterative critique and refinement")

        # Apply cross-encoder reranking
        top_techniques = self.cross_encoder.rerank_techniques(
            log_input.raw_summary,
            analysis_results['ranked_techniques'],
            top_k=12,
            log_input=log_input
        )
        search_method = analysis_results['search_method_used']

        # Generate initial analysis
        initial_analysis = self.generator.generate_analysis(
            log_input.raw_summary,
            top_techniques,
            search_method,
            analysis_results.get('coverage_score', 0)
        )

        # Iterative critique
        iterative_results = self.critic.iterative_critique_analysis(
            log_input, top_techniques, initial_analysis, max_iterations=self.max_iterations, retriever=self.retriever
        )

        # Apply refinements if needed
        if not iterative_results['coverage_achieved']:
            print(f"[INFO] Coverage threshold not met, applying refinements")
            refined_analysis = self._apply_dynamic_refinements(
                log_input, analysis_results, iterative_results, search_method
            )
        else:
            print(f"[INFO] Coverage threshold achieved")
            refined_analysis = initial_analysis
            refined_analysis['refinement_applied'] = False

        # Add comprehensive metadata
        self._add_metadata(refined_analysis, log_input, analysis_results, iterative_results)

        return refined_analysis

    def _apply_dynamic_refinements(self, log_input: MitreAgentInput, analysis_results: Dict,
                                   iterative_results: Dict, search_method: str) -> Dict[str, Any]:
        """Apply refinements with dynamic k adjustment."""
        additional_queries = iterative_results['all_additional_queries']
        additional_techniques = {}

        # Get recommended k value from critique
        dynamic_k = iterative_results['final_critique']['recommended_k']
        print(f"[DEBUG] Using dynamic k={dynamic_k} for refinement queries")

        for query in additional_queries:
            print(f"[DEBUG] Refinement query: '{query}' using {search_method} with k={dynamic_k}")
            techniques = self._retrieve_techniques(query, search_method, k=dynamic_k)

            for tech in techniques:
                additional_techniques[tech['attack_id']] = tech

        # Merge with existing techniques
        all_techniques_updated = {**analysis_results['all_techniques'], **additional_techniques}
        refined_ranking = self.ranker.rank_techniques_by_relevance(all_techniques_updated, log_input)

        # Generate refined analysis with more techniques
        refined_analysis = self.generator.generate_analysis(
            log_input.raw_summary,
            refined_ranking[:15],  # Use more techniques for refined analysis
            search_method,
            analysis_results.get('coverage_score', 0)
        )

        refined_analysis.update({
            'refinement_applied': True,
            'additional_queries_used': additional_queries,
            'dynamic_k_used': dynamic_k,
            'additional_techniques_found': len(additional_techniques),
            'iterations_performed': iterative_results['iterations_performed']
        })

        return refined_analysis

    def _retrieve_techniques(self, query: str, search_method: str, k: int = 5) -> list:
        """Retrieve techniques using specified method and k value."""
        print(f"[DEBUG] Executing query: '{query}' with {search_method}, k={k}")

        if search_method == "hybrid":
            return self.retriever.hybrid_search(query, k=k)
        elif search_method == "bm25":
            return self.retriever.bm25_search(query, k=k)
        elif search_method == "semantic":
            return self.retriever.semantic_search(query, k=k)
        else:
            return self.retriever.hybrid_search(query, k=k)

    def _add_metadata(self, analysis: Dict, log_input: MitreAgentInput, analysis_results: Dict, iterative_results: Dict):
        """Add comprehensive metadata to the final analysis."""
        final_critique = iterative_results['final_critique']

        analysis.update({
            'input_analysis_id': log_input.analysis_id,
            'input_severity': log_input.severity.value,
            'input_analysis_type': log_input.analysis_type.value,
            'input_affected_systems': log_input.affected_systems,
            'input_event_types': log_input.event_types,
            'input_processes': log_input.processes,
            'input_log_sources': log_input.log_sources,

            # Analysis process metadata
            'total_techniques_considered': analysis_results.get('total_unique_techniques', 0),
            'coverage_score': final_critique.get('coverage_score', 0),
            'coverage_achieved': iterative_results.get('coverage_achieved', False),
            'identified_gaps': final_critique.get('identified_gaps', []),
            'gap_priorities': final_critique.get('gap_priority', {}),

            # Technique details (top 10)
            'technique_details': analysis_results.get('ranked_techniques', [])[:10],

            # Process tracking
            'search_method_used': analysis_results.get('search_method_used', 'unknown'),
            'plan_used': analysis_results.get('plan', {}),
            'reasoning_trace': analysis_results.get('reasoning_trace', []),
            'iterations_performed': iterative_results.get('iterations_performed', 0),
            'dynamic_k_recommended': final_critique.get('recommended_k', 5),

            # Timestamps
            'processing_timestamp': datetime.now().isoformat(),
            'analysis_duration': None  # Could add timing if needed
        })

    def get_analysis_summary(self, analysis_result: Dict) -> Dict[str, Any]:
        """Generate a concise summary of the analysis results."""
        top_techniques = []
        for tech in analysis_result.get('technique_details', [])[:5]:
            tech_name = f"{tech.get('attack_id', 'Unknown')}: {tech.get('name', 'Unknown')}"
            top_techniques.append(tech_name)

        return {
            "analysis_id": analysis_result.get('input_analysis_id'),
            "severity": analysis_result.get('input_severity'),
            "coverage_score": analysis_result.get('coverage_score', 0),
            "techniques_found": len(analysis_result.get('technique_details', [])),
            "top_techniques": top_techniques,
            "refinement_applied": analysis_result.get('refinement_applied', False),
            "gaps_identified": len(analysis_result.get('identified_gaps', [])),
            "processing_time": analysis_result.get('processing_timestamp')
        }

if __name__ == "__main__":
    from mitre_example_input import create_sample_log_input, create_elaborate_mockup_incident
    import time

    print("Testing MitreAgent...")
    print("="*60)

    # Initialize agent
    agent = MitreAgent(
        llm_provider="google",
        model_name="gemini-2.0-flash",
        max_iterations=3
    )

    # Create sample input
    sample_input = create_sample_log_input()

    print(f"Testing with sample input: {sample_input.analysis_id}")
    print(f"Severity: {sample_input.severity.value}")
    print(f"Analysis type: {sample_input.analysis_type.value}")
    print(f"Affected systems: {sample_input.affected_systems}")

    print("\n" + "="*40)
    print("Testing analysis pipeline...")

    start_time = time.time()
    try:
        analysis_result = agent.analyze_threat(sample_input)
        end_time = time.time()

        # Analysis metadata
        print(f"\n{'='*50}")
        print("ANALYSIS METADATA")
        print(f"{'='*50}")
        print(f"- Processing time: {end_time - start_time:.2f} seconds")
        print(f"- Model used: {agent.generator.model_name}")
        print(f"- LLM provider: {agent.generator.llm_provider}")
        print(f"- Temperature: {agent.generator.temperature}")
        print(f"- Max iterations: {agent.max_iterations}")
        print(f"- Retrieval method: {analysis_result.get('search_method_used', 'unknown')}")

        # Retrieval metadata
        retrieval_stats = analysis_result.get('retrieval_stats', {})
        print(f"\nRetrieval Statistics:")
        print(f"- Total retrieved: {retrieval_stats.get('total_retrieved', 0)}")
        print(f"- Main techniques: {retrieval_stats.get('main_techniques', 0)}")
        print(f"- Sub-techniques: {retrieval_stats.get('sub_techniques', 0)}")

        print("Planning metadata:")
        plan = analysis_result.get('plan_used', {})
        print(f"- Objective: {plan.get('objective', 'N/A')}")
        print(f"- Priority areas: {plan.get('priority_areas', [])}")
        print(f"- Search strategy: {plan.get('search_strategy', 'N/A')}")
        print(f"- Expected tactics: {plan.get('expected_tactics', [])}")

        print("- Reasoning trace:")
        for step in analysis_result.get('reasoning_trace', []):
            print(f"  * {step}")


        print("Planned queries executed:")
        for area, result in analysis_result.get('planned_results', {}).items():
            print(f"  - {area}: {result['technique_count']} techniques, {len(result['queries_used'])} queries")
        print(f"- Total planned areas: {len(analysis_result.get('planned_results', {}))}")

        print(f"\nAnalysis Results:")
        print(f"- Analysis ID: {analysis_result.get('input_analysis_id')}")
        print(f"- Total techniques considered: {analysis_result.get('total_techniques_considered', 0)}")
        print(f"- Coverage score: {analysis_result.get('coverage_score', 0):.2f}")
        print(f"- Coverage achieved: {analysis_result.get('coverage_achieved', False)}")
        print(f"- Iterations performed: {analysis_result.get('iterations_performed', 0)}")
        print(f"- Refinement applied: {analysis_result.get('refinement_applied', False)}")
        print(f"- Evidence-backed statements: {analysis_result.get('evidence_backed_statements', 0)}")
        print(f"- Speculative statements: {analysis_result.get('speculative_statements', 0)}")



        if analysis_result.get('additional_queries_used'):
            print(f"- Additional queries: {len(analysis_result['additional_queries_used'])}")

        print(f"\nTop 10 techniques:")
        for i, tech in enumerate(analysis_result.get('technique_details', [])[:10], 1):
            score = tech.get('relevance_score', 0)
            print(f"  {i}. {tech['attack_id']}: {tech['name']} (Score: {score:.2f})")

        if analysis_result.get('identified_gaps'):
            print(f"\nIdentified gaps:")
            for gap in analysis_result['identified_gaps']:
                print(f"  - {gap}")

        # Test analysis summary
        print(f"\n" + "="*30)
        print("Testing analysis summary...")
        summary = agent.get_analysis_summary(analysis_result)
        print(f"Summary: {summary}")

        print(f"\nAnalysis preview:")
        analysis_text = analysis_result.get('analysis', 'No analysis generated')
        print(analysis_text)

        # Quality metrics
        print(f"\n{'='*50}")
        print("QUALITY METRICS")
        print(f"{'='*50}")
        confidence = analysis_result.get('confidence', 0)
        evidence_ratio = analysis_result.get('evidence_backed_statements', 0) / max(analysis_result.get('speculative_statements', 1), 1)
        print(f"- Overall confidence: {confidence:.2f}")
        print(f"- Evidence to speculation ratio: {evidence_ratio:.2f}")


    except Exception as e:
        print(f"Error during analysis: {e}")
        print(f"[ERROR] Analysis failed: {e}")

    # Test full analysis pipeline