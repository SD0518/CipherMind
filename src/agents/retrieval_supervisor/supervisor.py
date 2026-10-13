"""
Retrieval Supervisor - Coordinates CTI Agent, Database Agent, and Grader Agent

This supervisor manages the retrieval pipeline for cybersecurity analysis, coordinating
multiple specialized agents to provide comprehensive threat intelligence and MITRE ATT&CK
technique retrieval.
"""

import json
import os
from typing import Dict, Any, List, Optional
from pathlib import Path
from langchain_core.messages import convert_to_messages

# LangGraph and LangChain imports
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from langchain.chat_models import init_chat_model
from langgraph.prebuilt import create_react_agent
from langgraph_supervisor import create_supervisor

# Import your agent classes
from src.agents.cti_agent.cti_agent import CTIAgent
from src.agents.database_agent.agent import DatabaseAgent

# Import prompts
from src.agents.retrieval_supervisor.prompts import (
    GRADER_AGENT_PROMPT,
    SUPERVISOR_PROMPT_TEMPLATE,
    INPUT_MESSAGE_TEMPLATE,
    LOG_ANALYSIS_SECTION_TEMPLATE,
    CONTEXT_SECTION_TEMPLATE,
)


class RetrievalSupervisor:
    """
    Retrieval Supervisor that coordinates CTI Agent, Database Agent, and Grader Agent
    using LangGraph's supervisor pattern for comprehensive threat intelligence retrieval.
    """

    def __init__(
        self,
        llm_model: str = "google_genai:gemini-2.0-flash",
        kb_path: str = "./cyber_knowledge_base",
        max_iterations: int = 3,
        llm_client=None,
    ):
        """
        Initialize the Retrieval Supervisor.

        Args:
            llm_model: Specific model to use
            kb_path: Path to the cyber knowledge base
            max_iterations: Maximum iterations for the retrieval pipeline
            llm_client: Optional pre-initialized LLM client (overrides llm_model)
        """
        self.max_iterations = max_iterations
        self.llm_model = llm_model

        # Initialize the supervisor LLM
        if llm_client:
            self.llm_client = llm_client
            print(f"[INFO] Retrieval Supervisor: Using provided LLM client")
        elif "gpt-oss" in llm_model:
            reasoning_effort = "low"
            reasoning_format = "hidden"
            self.llm_client = init_chat_model(
                llm_model,
                temperature=0.1,
                reasoning_effort=reasoning_effort,
                reasoning_format=reasoning_format,
            )
            print(
                f"[INFO] Retrieval Supervisor: Using GPT-OSS model: {llm_model} with reasoning effort: {reasoning_effort}"
            )
        else:
            self.llm_client = init_chat_model(llm_model, temperature=0.1)
            print(f"[INFO] Retrieval Supervisor: Initialized with {llm_model}")

        # Initialize agents
        # self.cti_agent = self._initialize_cti_agent()
        self.database_agent = self._initialize_database_agent(kb_path)
        self.grader_agent = self._initialize_grader_agent()

        # Create the supervisor
        self.supervisor = self._create_supervisor()

    def _initialize_cti_agent(self) -> CTIAgent:
        """Initialize the CTI Agent."""
        try:
            cti_agent = CTIAgent(llm=self.llm_client)
            print("CTI Agent initialized successfully")
            return cti_agent
        except Exception as e:
            print(f"Failed to initialize CTI Agent: {e}")
            raise

    def _initialize_database_agent(self, kb_path: str) -> DatabaseAgent:
        """Initialize the Database Agent."""
        try:
            database_agent = DatabaseAgent(
                kb_path=kb_path,
                llm_client=self.llm_client,
            )
            print("Database Agent initialized successfully")
            return database_agent
        except Exception as e:
            print(f"Failed to initialize Database Agent: {e}")
            raise

    def _initialize_grader_agent(self):
        """Initialize the Grader Agent as a ReAct agent with no tools."""
        return create_react_agent(
            model=self.llm_client,
            tools=[],  # No tools for grader
            prompt=GRADER_AGENT_PROMPT,
            name="retrieval_grader_agent",
        )

    def _create_supervisor(self):
        """Create the supervisor using langgraph_supervisor."""

        # Prepare agent list with CompiledStateGraph objects
        agents = [
            self.database_agent.agent,  # Database Agent's ReAct agent
            self.grader_agent,  # Grader Agent (ReAct agent)
        ]

        # Format supervisor prompt with max_iterations
        supervisor_prompt = SUPERVISOR_PROMPT_TEMPLATE.format(
            max_iterations=self.max_iterations
        )

        return create_supervisor(
            model=self.llm_client,
            agents=agents,
            prompt=supervisor_prompt,
            add_handoff_back_messages=True,
            # output_mode="full_history",
            supervisor_name="retrieval_supervisor",
        ).compile(name="retrieval_supervisor")

    def invoke(
        self,
        query: str,
        log_analysis_report: Optional[Dict[str, Any]] = None,
        context: Optional[str] = None,
        trace: bool = False,
    ) -> Dict[str, Any]:
        """
        Invoke the retrieval supervisor pipeline.

        Args:
            query: The intelligence retrieval query/task
            log_analysis_report: Optional log analysis report from log analysis agent
            context: Optional additional context
            trace: Whether to trace the pipeline
        Returns:
            Dictionary containing the structured retrieval results
        """
        try:
            # Build the input message with context
            input_content = self._build_input_message(
                query, log_analysis_report, context
            )

            # Initialize state
            initial_state = {"messages": [HumanMessage(content=input_content)]}

            # print("\n" + "=" * 60)
            # print("RETRIEVAL SUPERVISOR PIPELINE STARTING")
            # print("=" * 60)
            # print(f"Query: {query}")
            # if log_analysis_report:
            #     print(
            #         f"Log Analysis Report Assessment: {log_analysis_report.get('overall_assessment', 'Unknown')} assessment"
            #     )
            # print()

            # Execute the supervisor pipeline
            raw_result = self.supervisor.invoke(initial_state)

            if trace:
                self._print_trace_pipeline(raw_result)

            # Parse structured output from the supervisor
            structured_result = self._parse_supervisor_output(raw_result, query)

            return structured_result
        except Exception as e:
            print(f"[ERROR] Retrieval Supervisor pipeline failed: {e}")
            raise

    def invoke_direct_query(self, query: str, trace: bool = False) -> Dict[str, Any]:
        """Invoke the retrieval supervisor pipeline with a direct query."""
        raw_result = self.supervisor.invoke({"messages": [HumanMessage(content=query)]})
        if trace:
            self._print_trace_pipeline(raw_result)

        # Parse structured output from the supervisor
        structured_result = self._parse_supervisor_output(raw_result, query)
        return structured_result

    def stream(
        self,
        query: str,
        log_analysis_report: Optional[Dict[str, Any]] = None,
        context: Optional[str] = None,
    ):
        # Build the input message with context
        input_content = self._build_input_message(query, log_analysis_report, context)

        # Initialize state
        initial_state = {"messages": [HumanMessage(content=input_content)]}

        for chunk in self.supervisor.stream(initial_state, subgraphs=True):
            self._pretty_print_messages(chunk, last_message=True)

    def _pretty_print_message(self, message, indent=False):
        pretty_message = message.pretty_repr(html=True)
        if not indent:
            print(pretty_message)
            return

        indented = "\n".join("\t" + c for c in pretty_message.split("\n"))
        print(indented)

    def _pretty_print_messages(self, update, last_message=False):
        is_subgraph = False
        if isinstance(update, tuple):
            ns, update = update
            # skip parent graph updates in the printouts
            if len(ns) == 0:
                return

            graph_id = ns[-1].split(":")[0]
            print(f"Update from subgraph {graph_id}:")
            print("\n")
            is_subgraph = True

        for node_name, node_update in update.items():
            update_label = f"Update from node {node_name}:"
            if is_subgraph:
                update_label = "\t" + update_label

            print(update_label)
            print("\n")

            messages = convert_to_messages(node_update["messages"])
            if last_message:
                messages = messages[-1:]

            for m in messages:
                self._pretty_print_message(m, indent=is_subgraph)
            print("\n")

    def _print_trace_pipeline(self, result: Dict[str, Any]):
        """Print detailed trace of the pipeline execution with message flow."""
        messages = result.get("messages", [])

        if not messages:
            print("[TRACE] No messages found in pipeline result")
            return

        print("\n" + "=" * 60)
        print("PIPELINE EXECUTION TRACE")
        print("=" * 60)

        # Print all messages with detailed formatting
        for i, msg in enumerate(messages, 1):
            print(f"\n--- Message {i} ---")

            if isinstance(msg, HumanMessage):
                print(f"[Human] {msg.content}")

            elif isinstance(msg, AIMessage):
                agent_name = getattr(msg, "name", None) or "agent"
                print(f"[Agent:{agent_name}] {msg.content}")

                # Check for function calls
                if (
                    hasattr(msg, "additional_kwargs")
                    and "function_call" in msg.additional_kwargs
                ):
                    fc = msg.additional_kwargs["function_call"]
                    print(f"  [ToolCall] {fc.get('name')}: {fc.get('arguments')}")

            elif isinstance(msg, ToolMessage):
                tool_name = getattr(msg, "name", None) or "tool"
                content = (
                    msg.content if isinstance(msg.content, str) else str(msg.content)
                )
                # Truncate long content for readability
                preview = content[:300] + ("..." if len(content) > 300 else "")
                print(f"[Tool:{tool_name}] {preview}")

            else:
                print(f"[Message] {getattr(msg, 'content', '')}")

        # Print final supervisor decision if available
        if messages:
            latest_message = messages[-1]
            if isinstance(latest_message, AIMessage):
                print(f"\n--- Final Supervisor Output ---")
                print(latest_message.content)

                # Check if this looks like a grader decision
                if "decision" in latest_message.content.lower():
                    try:
                        # Try to parse JSON decision
                        content = latest_message.content
                        if "{" in content and "}" in content:
                            start = content.find("{")
                            end = content.rfind("}") + 1
                            decision_json = json.loads(content[start:end])

                            decision = decision_json.get("decision", "unknown")
                            print(
                                f"\n[SUCCESS] Pipeline completed - Decision: {decision}"
                            )

                            if decision == "ACCEPT":
                                print("Results accepted by grader")
                            elif decision == "NEEDS_MITRE":
                                print("Additional MITRE technique analysis needed")

                    except (json.JSONDecodeError, KeyError):
                        print("\n[INFO] Pipeline completed (decision parsing failed)")

        print("\n" + "=" * 60)
        print("TRACE COMPLETED")
        print("=" * 60)

    def _build_input_message(
        self,
        query: str,
        log_analysis_report: Optional[Dict[str, Any]],
        context: Optional[str],
    ) -> str:
        """Build the input message for the supervisor."""

        # Build log analysis section
        log_analysis_section = ""
        if log_analysis_report:
            log_analysis_section = LOG_ANALYSIS_SECTION_TEMPLATE.format(
                log_analysis_report=json.dumps(log_analysis_report, indent=2)
            )

        # Build context section
        context_section = ""
        if context:
            context_section = CONTEXT_SECTION_TEMPLATE.format(context=context)

        # Build complete input message
        input_message = INPUT_MESSAGE_TEMPLATE.format(
            query=query,
            log_analysis_section=log_analysis_section,
            context_section=context_section,
        )

        return input_message

    def _parse_supervisor_output(
        self, raw_result: Dict[str, Any], original_query: str
    ) -> Dict[str, Any]:
        """Parse the supervisor's structured output from the raw result."""
        messages = raw_result.get("messages", [])

        # Look for the final supervisor message with structured JSON output
        final_supervisor_message = None
        for msg in reversed(messages):
            if (
                hasattr(msg, "name")
                and msg.name == "supervisor"
                and hasattr(msg, "content")
                and msg.content
            ):
                final_supervisor_message = msg.content
                break

        if not final_supervisor_message:
            # Fallback: use the last message
            if messages:
                final_supervisor_message = (
                    messages[-1].content if hasattr(messages[-1], "content") else ""
                )

        # Try to extract JSON from the supervisor's final message
        structured_output = self._extract_json_from_content(final_supervisor_message)

        if structured_output:
            # Validate and enhance the structured output
            return self._validate_and_enhance_output(
                structured_output, original_query, messages
            )
        else:
            # Fallback: create structured output from message analysis
            return self._create_fallback_output(messages, original_query)

    def _extract_json_from_content(self, content: str) -> Optional[Dict[str, Any]]:
        """Extract JSON from supervisor message content."""
        if not content:
            return None

        # Look for JSON blocks
        if "```json" in content:
            json_blocks = content.split("```json")
            for block in json_blocks[1:]:
                json_str = block.split("```")[0].strip()
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    continue

        # Look for any JSON-like structures
        start_idx = 0
        while True:
            start_idx = content.find("{", start_idx)
            if start_idx == -1:
                break

            # Find matching closing brace
            brace_count = 0
            end_idx = start_idx
            for i in range(start_idx, len(content)):
                if content[i] == "{":
                    brace_count += 1
                elif content[i] == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        end_idx = i + 1
                        break

            if brace_count == 0:
                json_str = content[start_idx:end_idx]
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    pass

            start_idx += 1

        return None

    def _validate_and_enhance_output(
        self, structured_output: Dict[str, Any], original_query: str, messages: List
    ) -> Dict[str, Any]:
        """Validate and enhance the structured output."""
        # Ensure required fields exist
        if "status" not in structured_output:
            structured_output["status"] = "SUCCESS"

        if "final_assessment" not in structured_output:
            structured_output["final_assessment"] = "ACCEPTED"

        if "retrieved_techniques" not in structured_output:
            structured_output["retrieved_techniques"] = []

        if "agents_used" not in structured_output:
            # Extract agents used from messages
            agents_used = set()
            for msg in messages:
                if hasattr(msg, "name") and msg.name:
                    agents_used.add(str(msg.name))
            structured_output["agents_used"] = list(agents_used)

        if "summary" not in structured_output:
            technique_count = len(structured_output.get("retrieved_techniques", []))
            structured_output["summary"] = (
                f"Retrieved {technique_count} MITRE techniques for analysis"
            )

        if "iteration_count" not in structured_output:
            structured_output["iteration_count"] = 1

        # Add metadata
        structured_output["query"] = original_query
        structured_output["total_techniques"] = len(
            structured_output.get("retrieved_techniques", [])
        )

        return structured_output

    def _create_fallback_output(
        self, messages: List, original_query: str
    ) -> Dict[str, Any]:
        """Create fallback structured output when JSON parsing fails."""
        # Extract techniques from database agent messages
        techniques = []
        agents_used = set()

        for msg in messages:
            if hasattr(msg, "name") and msg.name:
                agents_used.add(str(msg.name))

                # Look for database agent results
                if "database" in str(msg.name).lower() and hasattr(msg, "content"):
                    try:
                        # Try to extract techniques from tool messages
                        if hasattr(msg, "name") and "search_techniques" in str(
                            msg.name
                        ):
                            tool_data = (
                                json.loads(msg.content)
                                if isinstance(msg.content, str)
                                else msg.content
                            )
                            if "techniques" in tool_data:
                                for tech in tool_data["techniques"]:
                                    # Convert tactics to list format
                                    tactics = tech.get("tactics", [])
                                    if isinstance(tactics, str):
                                        tactics = [tactics] if tactics else []
                                    elif not isinstance(tactics, list):
                                        tactics = []

                                    technique = {
                                        "technique_id": tech.get("attack_id", ""),
                                        "technique_name": tech.get("name", ""),
                                        "tactic": tactics,  # Now as list
                                        "description": tech.get("description", ""),
                                        "relevance_score": tech.get(
                                            "relevance_score", 0.5
                                        ),
                                    }
                                    techniques.append(technique)
                    except (json.JSONDecodeError, TypeError, AttributeError):
                        continue

        return {
            "status": "PARTIAL",
            "final_assessment": "NEEDS_MORE_INFO",
            "retrieved_techniques": techniques,
            "agents_used": list(agents_used),
            "summary": f"Retrieved {len(techniques)} MITRE techniques (fallback parsing)",
            "iteration_count": 1,
            "query": original_query,
            "total_techniques": len(techniques),
            "parsing_method": "fallback",
        }

    def _process_results(
        self, result: Dict[str, Any], original_query: str
    ) -> Dict[str, Any]:
        """Process and format the supervisor results."""

        messages = result.get("messages", [])

        # Extract information from messages
        agents_used = set()
        cti_results = []
        database_results = []
        grader_decisions = []

        for msg in messages:
            if hasattr(msg, "name"):
                agent_name = msg.name
                if agent_name:  # ignore None or empty
                    agents_used.add(str(agent_name))

                if agent_name == "database_agent":
                    database_results.append(msg.content)
                elif agent_name == "retrieval_grader_agent":
                    grader_decisions.append(msg.content)

        # Get final supervisor message
        final_message = ""
        for msg in reversed(messages):
            if (
                isinstance(msg, AIMessage)
                and hasattr(msg, "name")
                and msg.name == "supervisor"
            ):
                final_message = msg.content
                break

        # Determine final assessment
        final_assessment = self._determine_final_assessment(
            grader_decisions, final_message
        )

        # Extract recommendations
        recommendations = self._extract_recommendations(
            cti_results, database_results, grader_decisions
        )

        return {
            "status": "SUCCESS",
            "query": original_query,
            "agents_used": [
                a for a in list(agents_used) if isinstance(a, str) and a.strip()
            ],
            "results": {
                "cti_intelligence": cti_results,
                "mitre_techniques": database_results,
                "quality_assessments": grader_decisions,
                "supervisor_synthesis": final_message,
            },
            "final_assessment": final_assessment,
            "recommendations": recommendations,
            "message_history": messages,
            "summary": self._generate_summary(
                cti_results, database_results, final_assessment
            ),
        }

    def _determine_final_assessment(
        self, grader_decisions: List[str], final_message: str
    ) -> str:
        """Determine the final assessment based on grader decisions."""

        # Look for the latest grader decision
        if grader_decisions:
            latest_decision = grader_decisions[-1]
            try:
                # Try to parse JSON from grader
                if "{" in latest_decision and "}" in latest_decision:
                    start = latest_decision.find("{")
                    end = latest_decision.rfind("}") + 1
                    decision_json = json.loads(latest_decision[start:end])
                    return decision_json.get("decision", "UNKNOWN")
            except json.JSONDecodeError:
                pass

        # Fallback to content analysis
        content = (final_message + " " + " ".join(grader_decisions)).lower()
        if "accept" in content:
            return "ACCEPTED"
        elif "needs_both" in content:
            return "NEEDS_BOTH"
        elif "needs_cti" in content:
            return "NEEDS_CTI"
        elif "needs_mitre" in content:
            return "NEEDS_MITRE"
        else:
            return "COMPLETED"

    def _extract_recommendations(
        self,
        cti_results: List[str],
        database_results: List[str],
        grader_decisions: List[str],
    ) -> List[str]:
        """Extract actionable recommendations from the results."""

        recommendations = []

        # Standard recommendations based on results
        if cti_results:
            recommendations.append("Review CTI findings for threat actor attribution")
            recommendations.append("Implement IOC-based detection rules")

        if database_results:
            recommendations.append("Map detected techniques to defensive controls")
            recommendations.append("Update threat hunting playbooks")

        # Extract specific recommendations from grader
        for decision in grader_decisions:
            try:
                if "{" in decision and "}" in decision:
                    start = decision.find("{")
                    end = decision.rfind("}") + 1
                    decision_json = json.loads(decision[start:end])
                    suggestions = decision_json.get("improvement_suggestions", [])
                    recommendations.extend(suggestions)
            except json.JSONDecodeError:
                continue

        # Remove duplicates and limit
        unique_recommendations = list(dict.fromkeys(recommendations))
        return unique_recommendations[:5]  # Top 5 recommendations

    def _generate_summary(
        self, cti_results: List[str], database_results: List[str], final_assessment: str
    ) -> str:
        """Generate a concise summary of the retrieval results."""

        summary_parts = [
            f"Retrieval Status: {final_assessment}",
            f"CTI Sources Analyzed: {len(cti_results)}",
            f"MITRE Techniques Retrieved: {len(database_results)}",
        ]

        if cti_results:
            summary_parts.append("Threat intelligence gathered from external sources")
        if database_results:
            summary_parts.append("MITRE ATT&CK techniques mapped to findings")

        return " | ".join(summary_parts)

    def stream_invoke(
        self,
        query: str,
        log_analysis_report: Optional[Dict[str, Any]] = None,
        context: Optional[str] = None,
    ):
        """
        Stream the retrieval supervisor pipeline execution.

        Args:
            query: The intelligence retrieval query/task
            log_analysis_report: Optional log analysis report from log analysis agent
            context: Optional additional context

        Yields:
            Streaming updates from the supervisor pipeline
        """
        try:
            # Build the input message with context
            input_content = self._build_input_message(
                query, log_analysis_report, context
            )

            # Initialize state
            initial_state = {"messages": [HumanMessage(content=input_content)]}

            # print("\n" + "=" * 60)
            # print("RETRIEVAL SUPERVISOR PIPELINE STREAMING")
            # print("=" * 60)
            # print(f"Query: {query}")
            # print()

            # Stream the supervisor pipeline
            for chunk in self.supervisor.stream(initial_state):
                yield chunk

        except Exception as e:
            yield {"error": str(e)}


# Example usage and testing
def test_retrieval_supervisor():
    """Test the Retrieval Supervisor with sample data."""

    # Sample log analysis report
    sample_report = {
        "overall_assessment": "ABNORMAL",
        "total_events_analyzed": 245,
        "analysis_summary": "Detected suspicious PowerShell execution with base64 encoding and potential credential access attempts targeting LSASS process",
        "abnormal_events": [
            {
                "event_id": "4688",
                "event_description": "PowerShell process creation with encoded command parameter",
                "why_abnormal": "Base64 encoded command suggests obfuscation and evasion techniques",
                "severity": "HIGH",
                "potential_threat": "Defense evasion or malware execution",
                "attack_category": "defense_evasion",
            },
            {
                "event_id": "4656",
                "event_description": "Handle request to LSASS process memory",
                "why_abnormal": "Unusual access pattern to sensitive authentication process",
                "severity": "CRITICAL",
                "potential_threat": "Credential dumping attack",
                "attack_category": "credential_access",
            },
        ],
    }

    try:
        # Initialize supervisor
        supervisor = RetrievalSupervisor()

        # Test query
        query = "Analyze the detected PowerShell and LSASS access patterns. Provide threat intelligence on related attack campaigns and map to MITRE ATT&CK techniques."

        # Execute retrieval with trace enabled
        results = supervisor.invoke(
            query=query,
            log_analysis_report=sample_report,
            context="High-priority security incident requiring immediate threat intelligence",
            trace=True,
        )

        # Display results
        print("=" * 60)
        print("RETRIEVAL RESULTS SUMMARY")
        print("=" * 60)
        print(f"Status: {results['status']}")
        print(f"Final Assessment: {results['final_assessment']}")
        print(f"Agents Used: {', '.join(results['agents_used'])}")
        print(f"\nSummary: {results['summary']}")

        print("\nRecommendations:")
        for i, rec in enumerate(results["recommendations"], 1):
            print(f"{i}. {rec}")

        return results

    except Exception as e:
        print(f"Test failed: {e}")
        return None


if __name__ == "__main__":
    test_retrieval_supervisor()
