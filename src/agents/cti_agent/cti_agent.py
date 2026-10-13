import os
import re
import time
from typing import List, Dict, Any, Optional, Sequence, Annotated
from typing_extensions import TypedDict

from langchain.chat_models import init_chat_model
from langchain_core.prompts import ChatPromptTemplate
from langchain_tavily import TavilySearch
from langgraph.graph import END, StateGraph, START
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
# from langsmith.integrations.otel import configure
from langsmith import traceable, Client, get_current_run_tree
from dotenv import load_dotenv

from src.agents.cti_agent.config import (
    MODEL_NAME,
    CTI_SEARCH_CONFIG,
    CTI_PLANNER_PROMPT,
    CTI_REGEX_PATTERN,
    REPLAN_PROMPT,
)
from src.agents.cti_agent.cti_tools import CTITools

load_dotenv()

# configure(
#     project_name=os.getenv("LANGSMITH_PROJECT", "cti-agent-project"),
#     api_key=os.getenv("LANGSMITH_API_KEY")
# )

ls_client = Client(api_key=os.getenv("LANGSMITH_API_KEY"))

class CTIState(TypedDict):
    """State definition for CTI agent for ReWOO planning."""

    task: str
    plan_string: str
    steps: List
    results: dict
    structured_intelligence: dict
    result: str
    replans: int  # Track number of replans
    last_step_quality: str  # "correct", "ambiguous", or "incorrect"
    correction_reason: str  # Why we need to replan


# Messages-based state for supervisor compatibility
class CTIMessagesState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]


class CTIAgent:
    """CTI Agent with specialized threat intelligence tools."""

    def __init__(self, llm=None, tavily_api_key: str | None = None):
        load_dotenv()

        if llm is not None:
            self.llm = llm
        else:
            # fall back to config model, but this is the ONLY place
            from src.agents.cti_agent.config import MODEL_NAME
            self.llm = init_chat_model(MODEL_NAME, temperature=0.1)

        search_config = {
            **CTI_SEARCH_CONFIG,
            "api_key": tavily_api_key or os.getenv("TAVILY_API_KEY"),
        }
        self.cti_search = TavilySearch(**search_config)
        self.cti_tools = CTITools(self.llm, self.cti_search)

        # Create the planner
        prompt_template = ChatPromptTemplate.from_messages(
            [("user", CTI_PLANNER_PROMPT)]
        )
        self.planner = prompt_template | self.llm

        # Build the internal CTI graph (task-based)
        self.app = self._build_graph()

        # Build a messages-based wrapper graph for supervisor compatibility
        self.agent = self._build_messages_graph()

    @traceable(name="cti_planner")
    def _get_plan(self, state: CTIState) -> Dict[str, Any]:
        """
        Planner node: Creates a step-by-step CTI research plan.

        Args:
            state: Current state containing the task

        Returns:
            Dictionary with extracted steps and plan string
        """
        task = state["task"]
        result = self.planner.invoke({"task": task})
        result_text = result.content if hasattr(result, "content") else str(result)
        matches = re.findall(CTI_REGEX_PATTERN, result_text)
        return {"steps": matches, "plan_string": result_text}

    def _get_current_task(self, state: CTIState) -> Optional[int]:
        """
        Get the current task number to execute.

        Args:
            state: Current state

        Returns:
            Task number (1-indexed) or None if all tasks completed
        """
        if "results" not in state or state["results"] is None:
            return 1
        if len(state["results"]) == len(state["steps"]):
            return None
        else:
            return len(state["results"]) + 1

    def _log_tool_metrics(self, tool_name: str, execution_time: float, success: bool, result_quality: str = None):
        """Log custom metrics to LangSmith."""
        try:

            current_run = get_current_run_tree()
            if current_run:
                ls_client.create_feedback(
                    run_id=current_run.id,
                    key="tool_performance",
                    score=1.0 if success else 0.0,
                    value={
                        "tool": tool_name,
                        "execution_time": execution_time,
                        "success": success,
                        "quality": result_quality
                    }
                )
            else:
                # Log as project-level feedback if no active run
                ls_client.create_feedback(
                    project_id=os.getenv("LANGSMITH_PROJECT", "cti-agent-project"),
                    key="tool_performance",
                    score=1.0 if success else 0.0,
                    value={
                        "tool": tool_name,
                        "execution_time": execution_time,
                        "success": success,
                        "quality": result_quality
                    }
                )
        except Exception as e:
            print(f"Failed to log metrics: {e}")


    @traceable(name="cti_tool_execution")
    def _tool_execution(self, state: CTIState) -> Dict[str, Any]:
        """
        Executor node: Executes the specialized CTI tools for the current step.

        Args:
            state: Current state

        Returns:
            Dictionary with updated results
        """
        _step = self._get_current_task(state)
        _, step_name, tool, tool_input = state["steps"][_step - 1]

        _results = (state["results"].copy() or {}) if "results" in state else {}

        # Replace variables in tool input
        original_tool_input = tool_input
        for k, v in _results.items():
            tool_input = tool_input.replace(k, str(v))

        start_time = time.time()
        success = False

        # Execute the appropriate specialized tool
        try:
            if tool == "SearchCTIReports":
                result = self.cti_tools.search_cti_reports(tool_input)
            elif tool == "ExtractURL":
                if "," in original_tool_input:
                    parts = original_tool_input.split(",", 1)
                    search_result_ref = parts[0].strip()
                    index_part = parts[1].strip()
                else:
                    search_result_ref = original_tool_input.strip()
                    index_part = "0"

                # Extract index from index_part
                index = 0
                if "second" in index_part.lower():
                    index = 1
                elif "third" in index_part.lower():
                    index = 2
                elif index_part.isdigit():
                    index = int(index_part)
                elif "1" in index_part:
                    index = 1

                # Get the actual search result from previous results
                if search_result_ref in _results:
                    search_result = _results[search_result_ref]
                    result = self.cti_tools.extract_url_from_search(
                        search_result, index
                    )
                else:
                    result = f"Error: Could not find search result {search_result_ref} in previous results. Available keys: {list(_results.keys())}"
            elif tool == "FetchReport":
                result = self.cti_tools.fetch_report(tool_input)
            elif tool == "ExtractIOCs":
                result = self.cti_tools.extract_iocs(tool_input)
            elif tool == "IdentifyThreatActors":
                result = self.cti_tools.identify_threat_actors(tool_input)
            elif tool == "ExtractMITRETechniques":
                # Parse framework parameter if provided
                if "," in original_tool_input:
                    parts = original_tool_input.split(",", 1)
                    content_ref = parts[0].strip()
                    framework = parts[1].strip()
                else:
                    content_ref = original_tool_input.strip()
                    framework = "Enterprise"  # Default framework

                # Get content from previous results or use directly
                if content_ref in _results:
                    content = _results[content_ref]
                else:
                    content = tool_input

                result = self.cti_tools.extract_mitre_techniques(content, framework)
            elif tool == "LLM":
                llm_result = self.llm.invoke(tool_input)
                result = (
                    llm_result.content
                    if hasattr(llm_result, "content")
                    else str(llm_result)
                )
            else:
                result = f"Unknown tool: {tool}"
        except Exception as e:
            result = f"Error executing {tool}: {str(e)}"

        _results[step_name] = str(result)

        success = True
        execution_time = time.time() - start_time

        # Log metrics
        self._log_tool_metrics(tool, execution_time, success)

        return {"results": _results}

    @traceable(name="cti_solver")
    def _solve(self, state: CTIState) -> Dict[str, str]:
        """
        Solver node: Synthesizes the CTI findings into a comprehensive report.

        Args:
            state: Current state with all execution results

        Returns:
            Dictionary with the final CTI intelligence report
        """
        # Build comprehensive context with FULL results
        plan = ""
        full_results_context = "\n\n" + "=" * 80 + "\n"
        full_results_context += "COMPLETE EXECUTION RESULTS FOR ANALYSIS:\n"
        full_results_context += "=" * 80 + "\n\n"

        _results = state.get("results", {}) or {}

        for idx, (plan_desc, step_name, tool, tool_input) in enumerate(
            state["steps"], 1
        ):
            # Replace variable references in inputs for display
            display_input = tool_input
            for k, v in _results.items():
                display_input = display_input.replace(k, f"<{k}>")

            # Build the plan summary (truncated for readability)
            plan += f"\nStep {idx}: {plan_desc}\n"
            plan += f"{step_name} = {tool}[{display_input}]\n"

            # Add result summary to plan (truncated)
            if step_name in _results:
                result_preview = str(_results[step_name])[:800]
                plan += f"Result Preview: {result_preview}...\n"
            else:
                plan += "Result: Not executed\n"

            # Add FULL result to separate context section
            if step_name in _results:
                full_results_context += f"\n{'─'*80}\n"
                full_results_context += f"STEP {idx}: {step_name} ({tool})\n"
                full_results_context += f"{'─'*80}\n"
                full_results_context += f"INPUT: {display_input}\n\n"
                full_results_context += f"FULL OUTPUT:\n{_results[step_name]}\n"

        # Create solver prompt with full context
        prompt = f"""You are a Cyber Threat Intelligence analyst creating a final report.
    
        You have access to COMPLETE results from all CTI research steps below.
        
        IMPORTANT: 
        - Use the FULL EXECUTION RESULTS section below - it contains complete, untruncated data
        - Extract ALL specific IOCs, technique IDs, and actor details from the full results
        - Do not say "Report contains X IOCs" - actually LIST them from the results
        - If results contain structured data (JSON), parse and present it clearly
        
        {full_results_context}
        
        {'='*80}
        RESEARCH PLAN SUMMARY:
        {'='*80}
        {plan}
        
        {'='*80}
        ORIGINAL TASK: {state['task']}
        {'='*80}
        
        Now create a comprehensive threat intelligence report following this structure:
        
        ## Intelligence Sources
        [List the specific reports analyzed with title, source, and date]
        
        ## Threat Actors & Attribution
        [Present actual threat actor names, aliases, and campaign names found]
        [Include specific attribution details and confidence levels]
        
        ## MITRE ATT&CK Techniques Identified
        [List specific technique IDs (T####) and names found in the reports]
        [Provide brief description of what each technique means and why it's relevant]
        
        ## Indicators of Compromise (IOCs) Retrieved
        [Present actual IOCs extracted from reports - be specific and comprehensive]
        
        ### IP Addresses
        [List all IPs found, or state "None identified"]
        
        ### Domains
        [List all domains found, or state "None identified"]
        
        ### File Hashes
        [List all hashes with types, or state "None identified"]
        
        ### URLs
        [List all malicious URLs, or state "None identified"]
        
        ### Email Addresses
        [List all email patterns, or state "None identified"]
        
        ### File Names
        [List all malicious file names, or state "None identified"]
        
        ### Other Indicators
        [List any other indicators like registry keys, mutexes, etc.]
        
        ## Attack Patterns & Campaign Details
        [Describe specific attack flows and methods detailed in reports]
        [Include timeline information if available]
        [Note targeting information - industries, regions, etc.]
        
        ## Key Findings Summary
        [Provide 3-5 bullet points of the most critical findings]
        
        ## Intelligence Gaps
        [Note what information was NOT available in the reports]
        
        ---
        
        **CRITICAL INSTRUCTIONS:**
        1. Extract data from the FULL EXECUTION RESULTS section above
        2. If ExtractIOCs results are in JSON format, parse and list all IOCs
        3. If IdentifyThreatActors results contain Q&A format, extract all answers
        4. If ExtractMITRETechniques results contain technique IDs, list ALL of them
        5. Be comprehensive - don't summarize when you have specific data
        6. If you cannot find specific data in results, clearly state what's missing
        """

        # Invoke LLM with context
        result = self.llm.invoke(prompt)
        result_text = result.content if hasattr(result, "content") else str(result)

        return {"result": result_text}

    # Helper method to better structure results
    def _structure_results_for_solver(self, state: CTIState) -> str:
        """
        Helper method to structure results in a more accessible format for the solver.

        Returns:
            Formatted string with categorized results
        """
        _results = state.get("results", {}) or {}

        structured = {
            "searches": [],
            "reports": [],
            "iocs": [],
            "actors": [],
            "techniques": [],
        }

        # Categorize results by tool type
        for step_name, result in _results.items():
            # Find which tool produced this result
            for _, sname, tool, _ in state["steps"]:
                if sname == step_name:
                    if tool == "SearchCTIReports":
                        structured["searches"].append(
                            {"step": step_name, "result": result}
                        )
                    elif tool == "FetchReport":
                        structured["reports"].append(
                            {"step": step_name, "result": result}
                        )
                    elif tool == "ExtractIOCs":
                        structured["iocs"].append({"step": step_name, "result": result})
                    elif tool == "IdentifyThreatActors":
                        structured["actors"].append(
                            {"step": step_name, "result": result}
                        )
                    elif tool == "ExtractMITRETechniques":
                        structured["techniques"].append(
                            {"step": step_name, "result": result}
                        )
                    break

        # Format into readable sections
        output = []

        if structured["iocs"]:
            output.append("\n" + "=" * 80)
            output.append("EXTRACTED IOCs (Indicators of Compromise):")
            output.append("=" * 80)
            for item in structured["iocs"]:
                output.append(f"\nFrom {item['step']}:")
                output.append(str(item["result"]))

        if structured["actors"]:
            output.append("\n" + "=" * 80)
            output.append("IDENTIFIED THREAT ACTORS:")
            output.append("=" * 80)
            for item in structured["actors"]:
                output.append(f"\nFrom {item['step']}:")
                output.append(str(item["result"]))

        if structured["techniques"]:
            output.append("\n" + "=" * 80)
            output.append("EXTRACTED MITRE ATT&CK TECHNIQUES:")
            output.append("=" * 80)
            for item in structured["techniques"]:
                output.append(f"\nFrom {item['step']}:")
                output.append(str(item["result"]))

        if structured["reports"]:
            output.append("\n" + "=" * 80)
            output.append("FETCHED REPORTS (for context):")
            output.append("=" * 80)
            for item in structured["reports"]:
                output.append(f"\nFrom {item['step']}:")
                # Truncate report content but keep IOC sections visible
                report_text = str(item["result"])
                output.append(
                    report_text[:2000] + "..."
                    if len(report_text) > 2000
                    else report_text
                )

        return "\n".join(output)

    def _route(self, state: CTIState) -> str:
        """
        Routing function to determine next node.

        Args:
            state: Current state

        Returns:
            Next node name: "solve" or "tool"
        """
        _step = self._get_current_task(state)
        if _step is None:
            return "solve"
        else:
            return "tool"

    @traceable(name="cti_evaluator")
    def _evaluate_result(self, state: CTIState) -> Dict[str, Any]:
        """
        Evaluator node: Assesses quality of the last tool execution result.

        Returns:
            Dictionary with quality assessment and correction needs
        """
        _step = len(state.get("results", {}))
        if _step == 0:
            return {"last_step_quality": "correct"}

        current_step = state["steps"][_step - 1]
        _, step_name, tool, tool_input = current_step
        result = state["results"][step_name]

        # Evaluation prompt
        eval_prompt = f"""Evaluate if this CTI tool execution retrieved ACTUAL threat intelligence:
    
        Tool: {tool}
        Input: {tool_input}
        Result: {result[:1000]}
        
        Quality Criteria for Web Search:
        - CORRECT: Retrieved specific IOCs, technique IDs, actor names. A website that doesn't have the name of the actor or IOCs is not sufficient.
        - AMBIGUOUS: Retrieved general security content but lacks specific CTI details
        - INCORRECT: Retrieved irrelevant content, errors, or marketing material
        
        Quality Criteria for MITER Extraction:
        - CORRECT: Extracted valid MITRE ATT&CK technique IDs (e.g., T1234) or tactics (e.g., Initial Access)
        - AMBIGUOUS: Extracted general security terms but no valid technique IDs or tactics
        - INCORRECT: Extracted irrelevant content or no valid techniques/tactics
        
        Respond with ONLY one word: CORRECT, AMBIGUOUS, or INCORRECT
        
        If AMBIGUOUS or INCORRECT, also provide a brief reason (1 sentence).
        Format: QUALITY: [reason if needed]"""

        eval_result = self.llm.invoke(eval_prompt)
        eval_text = (
            eval_result.content if hasattr(eval_result, "content") else str(eval_result)
        )

        # Parse evaluation
        quality = "correct"
        reason = ""

        if "INCORRECT" in eval_text.upper():
            quality = "incorrect"
            reason = eval_text.split("INCORRECT:")[-1].strip()[:200]
        elif "AMBIGUOUS" in eval_text.upper():
            quality = "ambiguous"
            reason = eval_text.split("AMBIGUOUS:")[-1].strip()[:200]

        return {"last_step_quality": quality, "correction_reason": reason}

    def _replan(self, state: CTIState) -> Dict[str, Any]:
        """
        Replanner node: Creates corrected plan when results are inadequate.
        """
        replans = state.get("replans", 0)

        # Limit replanning attempts
        if replans >= 3:
            return {"replans": replans, "replan_status": "max_attempts_reached"}

        _step = len(state.get("results", {}))
        failed_step = state["steps"][_step - 1]
        _, step_name, tool, tool_input = failed_step

        # Store replan context for display
        replan_context = {
            "failed_step_number": _step,
            "failed_tool": tool,
            "failed_input": tool_input[:100],
            "problem": state.get("correction_reason", "Quality issues"),
            "original_plan": failed_step[0],
        }

        replan_prompt = REPLAN_PROMPT.format(
            task=state["task"],
            failed_step=failed_step[0],
            step_name=step_name,
            tool=tool,
            tool_input=tool_input,
            results=state["results"][step_name][:500],
            problem=state["correction_reason"],
            completed_steps=self._format_completed_steps(state),
            step=_step,
        )

        replan_result = self.llm.invoke(replan_prompt)
        replan_text = (
            replan_result.content
            if hasattr(replan_result, "content")
            else str(replan_result)
        )

        # Store the replan thinking for display
        replan_context["replan_thinking"] = (
            replan_text[:500] + "..." if len(replan_text) > 500 else replan_text
        )

        # Parse new step
        import re

        matches = re.findall(CTI_REGEX_PATTERN, replan_text)

        if matches:
            new_plan, new_step_name, new_tool, new_tool_input = matches[0]

            # Store the correction details
            replan_context["corrected_plan"] = new_plan
            replan_context["corrected_tool"] = new_tool
            replan_context["corrected_input"] = new_tool_input[:100]
            replan_context["success"] = True

            # Replace the failed step with corrected version
            new_steps = state["steps"].copy()
            new_steps[_step - 1] = matches[0]

            # Remove the failed result so it gets re-executed
            new_results = state["results"].copy()
            del new_results[step_name]

            return {
                "steps": new_steps,
                "results": new_results,
                "replans": replans + 1,
                "replan_context": replan_context,
            }
        else:
            replan_context["success"] = False
            replan_context["error"] = "Failed to parse corrected plan"

        return {"replans": replans + 1, "replan_context": replan_context}

    def _format_completed_steps(self, state: CTIState) -> str:
        """Helper to format completed steps for replanning context."""
        output = []
        for step in state["steps"][: len(state.get("results", {}))]:
            plan, step_name, tool, tool_input = step
            if step_name in state["results"]:
                output.append(f"{step_name} = {tool}[{tool_input}] ✓")
        return "\n".join(output)

    def _route_after_tool(self, state: CTIState) -> str:
        """Route to evaluator only after specific tools that retrieve external content."""
        _step = len(state.get("results", {}))
        if _step == 0:
            return "evaluate"

        current_step = state["steps"][_step - 1]
        _, step_name, tool, tool_input = current_step

        tools_to_evaluate = ["SearchCTIReports", "ExtractMITRETechniques"]

        if tool in tools_to_evaluate:
            return "evaluate"
        else:
            # Skip evaluation for extraction/analysis tools
            _next_step = self._get_current_task(state)
            if _next_step is None:
                return "solve"
            else:
                return "tool"

    def _route_after_eval(self, state: CTIState) -> str:
        """Route based on evaluation: replan, continue, or solve."""
        quality = state.get("last_step_quality", "correct")

        # Check if all steps are complete
        _step = self._get_current_task(state)

        if quality in ["ambiguous", "incorrect"]:
            # Need to replan this step
            return "replan"
        elif _step is None:
            # All steps complete and quality is good
            return "solve"
        else:
            # Continue to next tool
            return "tool"

    def _build_graph(self) -> StateGraph:
        """Build graph with corrective feedback loop."""
        graph = StateGraph(CTIState)

        # Add nodes
        graph.add_node("plan", self._get_plan)
        graph.add_node("tool", self._tool_execution)
        graph.add_node("evaluate", self._evaluate_result)
        graph.add_node("replan", self._replan)
        graph.add_node("solve", self._solve)

        # Add edges
        graph.add_edge(START, "plan")
        graph.add_edge("plan", "tool")
        graph.add_edge("replan", "tool")
        graph.add_edge("solve", END)

        # Conditional routing
        graph.add_conditional_edges("tool", self._route_after_tool)
        graph.add_conditional_edges("evaluate", self._route_after_eval)

        return graph.compile(name="cti_agent")

    # --- Messages-based wrapper for supervisor ---
    def _messages_node(self, state: CTIMessagesState) -> Dict[str, List[AIMessage]]:
        """Adapter node: take messages input, run CTI pipeline, return AI message.

        This allows the CTI agent to plug into a messages-based supervisor.
        """
        # Find the latest human message content as the task
        task_text = None
        for msg in reversed(state.get("messages", [])):
            if isinstance(msg, HumanMessage):
                task_text = msg.content
                break
        if not task_text and state.get("messages"):
            # Fallback: use the last message content
            task_text = state["messages"][-1].content
        if not task_text:
            task_text = "Provide cyber threat intelligence based on the context."

        # Run the internal CTI graph and extract final report text
        final_chunk = None
        for chunk in self.app.stream({"task": task_text}):
            final_chunk = chunk

        content = ""
        if isinstance(final_chunk, dict):
            solve_part = final_chunk.get("solve", {}) if final_chunk else {}
            content = solve_part.get("result", "") if isinstance(solve_part, dict) else ""
        if not content:
            # As a fallback, try a direct invoke to get final aggregated state
            try:
                agg_state = self.app.invoke({"task": task_text})
                if isinstance(agg_state, dict):
                    content = agg_state.get("result", "") or ""
            except Exception:
                pass
        if not content:
            content = "CTI agent completed, but no final report was produced."

        return {"messages": [AIMessage(content=content, name="cti_agent")]}

    def _build_messages_graph(self):
        """Build a minimal messages-based wrapper graph for supervisor usage."""
        graph = StateGraph(CTIMessagesState)
        graph.add_node("cti_adapter", self._messages_node)
        graph.add_edge(START, "cti_adapter")
        graph.add_edge("cti_adapter", END)
        return graph.compile(name="cti_agent")

    @traceable(name="cti_agent_full_run")
    def run(self, task: str) -> Dict[str, Any]:
        """
        Run the CTI agent on a given task.

        Args:
            task: The CTI research task/question to solve

        Returns:
            Final state after execution with comprehensive threat intelligence
        """
        run_metadata = {
            "task": task,
            "agent_version": "1.0",
            "timestamp": time.time()
        }

        try:
            final_state = None
            for state in self.app.stream({"task": task}):
                final_state = state

            # Log successful completion
            ls_client.create_feedback(
                run_id=None,
                key="run_completion",
                score=1.0,
                value={"status": "completed", "final_result_length": len(str(final_state))}
            )

            return final_state

        except Exception as e:
            # Log failure
            ls_client.create_feedback(
                run_id=None,
                key="run_completion",
                score=0.0,
                value={"status": "failed", "error": str(e)}
            )
            raise

    def stream(self, task: str):
        """
        Stream the CTI agent execution for a given task.

        Args:
            task: The CTI research task/question to solve

        Yields:
            State updates during execution
        """
        for state in self.app.stream({"task": task}):
            yield state


def format_cti_output(state: Dict[str, Any]) -> str:
    """Format the CTI agent output for better readability."""
    output = []

    for node_name, node_data in state.items():
        output.append(f"\n **{node_name.upper()} PHASE**")
        output.append("-" * 80)

        if node_name == "plan":
            if "plan_string" in node_data:
                output.append("\n**Research Plan:**")
                output.append(node_data["plan_string"])

            if "steps" in node_data and node_data["steps"]:
                output.append("\n**Planned Steps:**")
                for i, (plan, step_name, tool, tool_input) in enumerate(
                    node_data["steps"], 1
                ):
                    output.append(f"\n  Step {i}: {plan}")
                    output.append(f"  {step_name} = {tool}[{tool_input[:100]}...]")

        elif node_name == "tool":
            if "results" in node_data:
                output.append("\n**Tool Execution Results:**")
                for step_name, result in node_data["results"].items():
                    output.append(f"\n  {step_name}:")
                    result_str = str(result)
                    output.append(f"    {result_str}")

        elif node_name == "evaluate":
            # Show evaluation details
            quality = node_data.get("last_step_quality", "unknown")
            reason = node_data.get("correction_reason", "")

            output.append(f"**Quality Assessment:** {quality.upper()}")

            if reason:
                output.append(f"**Reason:** {reason}")

            # Determine next action based on quality
            if quality in ["ambiguous", "incorrect"]:
                output.append("**Decision:** Step needs correction - triggering replan")
            elif quality == "correct":
                output.append("**Decision:** Step quality acceptable - continuing")
            else:
                output.append(f"**Decision:** Quality assessment: {quality}")

        elif node_name == "replan":
            replans = node_data.get("replans", 0)
            output.append(f"**Replan Attempt:** {replans}")

            replan_context = node_data.get("replan_context", {})

            if replans >= 3:
                output.append("**Status:** Maximum replan attempts reached")
                output.append("**Action:** Proceeding with current results")
            elif replan_context:
                # Show detailed replan thinking
                output.append(
                    f"**Failed Step:** {replan_context.get('failed_step_number', 'Unknown')}"
                )
                output.append(
                    f"**Problem:** {replan_context.get('problem', 'Quality issues')}"
                )
                output.append(
                    f"**Original Tool:** {replan_context.get('failed_tool', 'Unknown')}[{replan_context.get('failed_input', '...')}]"
                )

                if "replan_thinking" in replan_context:
                    output.append(f"**Replan Analysis:**")
                    output.append(f"  {replan_context['replan_thinking']}")

                if replan_context.get("success", False):
                    output.append(
                        f"**Corrected Plan:** {replan_context.get('corrected_plan', 'Unknown')}"
                    )
                    output.append(
                        f"**New Tool:** {replan_context.get('corrected_tool', 'Unknown')}[{replan_context.get('corrected_input', '...')}]"
                    )
                    output.append("**Status:** Successfully generated improved plan")
                    output.append(
                        "**Action:** Step will be re-executed with new approach"
                    )
                else:
                    output.append(
                        f"**Error:** {replan_context.get('error', 'Unknown error')}"
                    )
                    output.append("**Status:** Failed to generate valid corrected plan")
            else:
                output.append("**Status:** Generating improved plan...")
                output.append("**Action:** Step will be re-executed with new approach")

        elif node_name == "solve":
            if "result" in node_data:
                output.append("\n**FINAL THREAT INTELLIGENCE REPORT:**")
                output.append("=" * 80)
                output.append(node_data["result"])

        output.append("")

    return "\n".join(output)


if __name__ == "__main__":
    # Example usage demonstrating the enhanced CTI capabilities
    task = """Find comprehensive threat intelligence about recent ransomware attacks targeting healthcare organizations"""

    print("\n" + "=" * 80)
    print("CTI AGENT - STARTING ANALYSIS")
    print("=" * 80)
    print(f"\nTask: {task}\n")

    # Initialize the agent
    agent = CTIAgent()

    # Stream the execution and display results
    for state in agent.stream(task):
        formatted_output = format_cti_output(state)
        print(formatted_output)
        print("\n" + "-" * 80 + "\n")

    print("\nCTI ANALYSIS COMPLETED!")
    print("=" * 80 + "\n")
