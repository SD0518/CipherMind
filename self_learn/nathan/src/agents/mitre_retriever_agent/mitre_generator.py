from typing import List, Dict, Any
from dotenv import load_dotenv
from langchain.prompts import PromptTemplate
from langchain_ollama import OllamaLLM
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from os import getenv
import os

class MitreGenerator:
    """MITRE ATT&CK generator that retrieves and formats in a natural-language answer."""

    def __init__(self,
                 llm_provider: str = "ollama",
                 model_name: str = "llama2",
                 temperature: float = 0.3):
        self.llm_provider = llm_provider
        self.model_name = model_name
        self.temperature = temperature

        # Initialize components
        self.llm = self._setup_llm()
        self.prompt = self._create_prompt()
        self.chain = self.prompt | self.llm

        print(f"[INFO] MitreAgent initialized with {llm_provider}:{model_name}")

    def _setup_llm(self):
        """Setup the language model."""
        print(f"[DEBUG] Setting up LLM: {self.llm_provider}")

        env_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '.env')
        env_path = os.path.abspath(env_path)

        load_dotenv(dotenv_path=env_path, override=True)

        if self.llm_provider == "ollama":
            return OllamaLLM(model=self.model_name, temperature=self.temperature)
        elif self.llm_provider == "openai":
            api_key = os.getenv("OPENAI_API_KEY")
            return ChatOpenAI(model=self.model_name, temperature=self.temperature, api_key=api_key)
        elif self.llm_provider.lower() == "google":
            return ChatGoogleGenerativeAI(
                model="gemini-2.0-flash-exp",
                api_key=getenv("GOOGLE_API_KEY"),
                temperature=self.temperature
            )
        else:
            raise ValueError(f"Unsupported LLM provider: {self.llm_provider}")

    @staticmethod
    def _create_prompt() -> PromptTemplate:
        return PromptTemplate(
            input_variables=["query", "techniques", "retrieval_method"],
            template="""You are a cybersecurity analyst expert in MITRE ATT&CK framework. Analyze the given security incident and retrieved techniques.

            **CRITICAL REQUIREMENTS:**
            1. ONLY make claims backed by evidence from the query or technique descriptions
            2. For each technique mentioned, cite specific evidence that supports it
            3. Mark speculative statements with "(Hypothetical)" prefix
            4. **ANALYZE ALL PROVIDED TECHNIQUES** - Do not skip techniques without clear justification
            5. Link mitigations directly to mentioned techniques
            
            **Incident Analysis:**
            Query: {query}
            
            **Retrieved MITRE Techniques:**
            {techniques}
            
            **Analysis Instructions step-by-step:**
            - Start with a confidence assessment (High/Medium/Low) based on evidence strength
            - **ANALYZE EACH TECHNIQUE**: For every technique provided, determine its relevance and evidence
            - Group techniques by evidence strength: Strong Evidence first, then Moderate, then Speculative
            - Explain the attack flow across all relevant techniques
            - Suggest specific mitigations for each mentioned technique
            
            **Response Format:**
            ## Confidence Assessment
            [High/Medium/Low based on evidence strength]
            
            ## Strong Evidence Techniques
            [For techniques with direct evidence matches, format as:]
            **{{technique_id}}: {{technique_name}}**
            - Evidence: "{{specific_evidence_from_query_or_description}}"
            - Relevance: [Why this technique fits the incident]
            - Mitigation: [Specific countermeasures for this technique]
    
            ## Moderate Evidence Techniques
            [For techniques with circumstantial evidence, format as:]
            **{{technique_id}}: {{technique_name}}**
            - Evidence: "{{circumstantial_evidence}}"
            - Relevance: [Why this technique might be relevant]
            - Mitigation: [Preventive countermeasures]
    
            ## Speculative Techniques
            [For techniques without direct evidence but tactically relevant]
            **(Hypothetical) {{technique_id}}: {{technique_name}}**
            - Speculation: [Why this technique could be involved]
            - Context: [How it fits the attack pattern]
            - Mitigation: [Proactive countermeasures]
            
            ## Attack Flow Analysis
            [Logical progression based on evidence]
            
            ## Mitigation Mapping Table
            | Technique ID | Technique Name | Priority Mitigations | Implementation Notes |
            |--------------|----------------|---------------------|---------------------|
            [Generate table with specific, actionable mitigations for each technique]
            
            ## Speculative Scenarios
            (Hypothetical) [Any scenarios not directly supported by evidence]
            
            ## Recommended Immediate Actions
            1. **High Priority**: [Actions for critical techniques with strong evidence]
            2. **Medium Priority**: [Actions for likely techniques]
            3. **Proactive Monitoring**: [Actions for speculative techniques]
    
            **IMPORTANT**: Analyze ALL provided techniques. Do not omit techniques unless they are clearly irrelevant to cybersecurity incidents."""
        )

    def generate_analysis(self, query: str, techniques: List[Dict], search_method: str, coverage_score: float) -> Dict[str, Any]:
        """Generate evidence-anchored analysis."""
        try:
            formatted_techniques = self._format_techniques_with_evidence(techniques)

            result = self.chain.invoke({
                "query": query,
                "techniques": formatted_techniques
            })

            analysis_content = result.content

            # Extract confidence from analysis
            confidence = self._extract_confidence(analysis_content, techniques, coverage_score)

            # Identify evidence-backed vs speculative statements
            evidence_statements, speculative_statements = self._categorize_statements(analysis_content)

            return {
                "query": query,
                "analysis": analysis_content,
                "techniques_used": [t["attack_id"] for t in techniques],
                "technique_details": techniques,
                "confidence": confidence,
                "retrieval_method": search_method,
                "evidence_backed_statements": len(evidence_statements),
                "speculative_statements": len(speculative_statements),
                "retrieval_stats": {
                    "total_retrieved": len(techniques),
                    "main_techniques": len([t for t in techniques if not t.get('is_subtechnique', False)]),
                    "sub_techniques": len([t for t in techniques if t.get('is_subtechnique', False)])
                }
            }
        except Exception as e:
            print(f"[ERROR] Analysis generation failed: {e}")
            return {
                "query": query,
                "analysis": "Analysis generation failed.",
                "techniques_used": [],
                "technique_details": [],
                "confidence": 0.0,
                "retrieval_method": search_method,
                "evidence_backed_statements": 0,
                "speculative_statements": 0,
                "retrieval_stats": {
                    "total_retrieved": 0,
                    "main_techniques": 0,
                    "sub_techniques": 0
                }
            }

    def _format_techniques_with_evidence(self, techniques: List[Dict]) -> str:
        """Format techniques with evidence highlighting."""
        if not techniques:
            return "No techniques retrieved."

        formatted = []
        for i, technique in enumerate(techniques, 1):
            attack_id = technique.get('attack_id', 'Unknown')
            name = technique.get('name', 'Unknown')
            tactics = ', '.join(technique.get('tactics', []))
            platforms = ', '.join(technique.get('platforms', []))
            is_sub = " (Sub-technique)" if technique.get('is_subtechnique', False) else ""
            relevance_score = technique.get('relevance_score', 0.0)

            # Include evidence matches if available
            evidence_matches = technique.get('evidence_matches', [])
            evidence_text = ""
            if evidence_matches:
                evidence_text = f"\n   - **Evidence**: {'; '.join(evidence_matches[:2])}"

            # Get description
            description = self._extract_description(technique)

            technique_text = f"""
            {i}. **{attack_id}**: {name}{is_sub}
               - **Tactics**: {tactics}
               - **Platforms**: {platforms}
               - **Relevance Score**: {relevance_score:.2f}
               - **Description**: {description}{evidence_text}
               - **Mitigations Available**: {technique.get('mitigation_count', 0)}"""

            formatted.append(technique_text.strip())

        return "\n\n".join(formatted)

    def _extract_description(self, technique: Dict) -> str:
        """Extract technique description."""
        description = ""
        if 'content' in technique:
            content_lines = technique['content'].split('\n')
            for line in content_lines:
                if line.startswith('Description:'):
                    description = line.replace('Description:', '').strip()[:250] + "..."
                    break

        if not description and 'description' in technique:
            description = technique['description'][:250] + "..."

        return description or "No description available"

    def _extract_confidence(self, analysis: str, techniques: List[Dict] = None, coverage_score: float = 0.0) -> float:
        """Calculate dynamic confidence based on evidence and coverage."""

        # Parse the actual confidence assessment section
        lines = analysis.split('\n')
        text_confidence = 0.5  # default

        for i, line in enumerate(lines):
            if '## Confidence Assessment' in line and i + 1 < len(lines):
                next_line = lines[i + 1].lower().strip()
                if 'high' in next_line:
                    text_confidence = 0.8
                elif 'medium' in next_line:
                    text_confidence = 0.6
                elif 'low' in next_line:
                    text_confidence = 0.4
                break

        # Count actual evidence from the structured sections
        strong_evidence = len([line for line in lines if line.strip().startswith('**T') and 'Strong Evidence' in analysis[:analysis.find(line)] if line in analysis])
        moderate_evidence = len([line for line in lines if line.strip().startswith('**T') and 'Moderate Evidence' in analysis[:analysis.find(line)] if line in analysis])

        total_techniques = len(techniques) if techniques else 1
        evidence_ratio = (strong_evidence * 1.0 + moderate_evidence * 0.5) / total_techniques

        # Use actual coverage score
        if techniques:
            coverage_score = len([t for t in techniques if t.get('relevance_score', 0) > 2.0]) / total_techniques


        # Combined confidence
        combined_confidence = (text_confidence * 0.4 +
                               evidence_ratio * 0.3 +
                               coverage_score * 0.3)

        return min(combined_confidence, 1.0)

    def _categorize_statements(self, analysis: str) -> tuple[List[str], List[str]]:
        """Categorize statements as evidence-backed or speculative."""
        lines = analysis.split('\n')
        evidence_statements = []
        speculative_statements = []

        for line in lines:
            if 'evidence:' in line.lower() or 'shows' in line.lower():
                evidence_statements.append(line.strip())
            elif '(hypothetical)' in line.lower() or 'may' in line.lower():
                speculative_statements.append(line.strip())

        return evidence_statements, speculative_statements

    def set_temperature(self, temperature: float):
        """Adjust model temperature."""
        print(f"[DEBUG] Setting temperature to {temperature}")
        self.temperature = temperature
        self.llm = self._setup_llm()
        self.chain = self.prompt | self.llm
