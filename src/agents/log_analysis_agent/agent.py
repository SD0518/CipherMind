"""
LogAnalysisAgent - Main orchestrator for cybersecurity log analysis
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

from langchain_core.messages import HumanMessage
from langgraph.prebuilt import create_react_agent
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END
from langchain.chat_models import init_chat_model

from langsmith import traceable, Client, get_current_run_tree

from src.agents.log_analysis_agent.state_models import AnalysisState
from src.agents.log_analysis_agent.utils import (
    get_llm,
    get_tools,
    format_execution_time,
    truncate_to_tokens,
)
from src.agents.log_analysis_agent.prompts import (
    ANALYSIS_PROMPT,
    CRITIC_FEEDBACK_TEMPLATE,
    SELF_CRITIC_PROMPT,
)


ls_client = Client(api_key=os.getenv("LANGSMITH_API_KEY"))


class LogAnalysisAgent:
    """
    Main orchestrator for cybersecurity log analysis.
    Coordinates the entire workflow: load → preprocess → analyze → save → display
    """

    def __init__(
        self,
        model_name: str = "google_genai:gemini-2.0-flash",
        temperature: float = 0.1,
        output_dir: str = "analysis",
        max_iterations: int = 2,
        llm_client=None,
    ):
        """
        Initialize the Log Analysis Agent

        Args:
            model_name: Name of the model to use (e.g. "google_genai:gemini-2.0-flash")
            temperature: Temperature for the model
            output_dir: Directory name for saving outputs (relative to package directory)
            max_iterations: Maximum number of iterations for the ReAct agent
            llm_client: Optional pre-initialized LLM client (overrides model_name/temperature)
        """
        if llm_client:
            self.llm = llm_client
            print(f"[INFO] Log Analysis Agent: Using provided LLM client")
        else:
            self.llm = init_chat_model(model_name, temperature=temperature)
            print(f"[INFO] Log Analysis Agent: Using default LLM model: {model_name}")

        self.base_tools = get_tools()

        self.output_root = Path(output_dir)
        self.output_root.mkdir(exist_ok=True)

        # Initialize helper components
        self.log_processor = LogProcessor(model_name=model_name)
        self.react_analyzer = ReactAnalyzer(
            self.llm, self.base_tools, max_iterations=max_iterations
        )
        self.result_manager = ResultManager(self.output_root)

        # Create workflow graph
        self.workflow = self._create_workflow()

    def _create_workflow(self) -> StateGraph:
        """Create and configure the analysis workflow graph"""
        workflow = StateGraph(AnalysisState)

        # Add nodes using instance methods
        workflow.add_node("load_logs", self.log_processor.load_logs)
        workflow.add_node("preprocess_logs", self.log_processor.preprocess_logs)
        workflow.add_node("react_agent_analysis", self.react_analyzer.analyze)
        workflow.add_node("save_results", self.result_manager.save_results)
        workflow.add_node("display_results", self.result_manager.display_results)

        # Define workflow edges
        workflow.set_entry_point("load_logs")
        workflow.add_edge("load_logs", "preprocess_logs")
        workflow.add_edge("preprocess_logs", "react_agent_analysis")
        workflow.add_edge("react_agent_analysis", "save_results")
        workflow.add_edge("save_results", "display_results")
        workflow.add_edge("display_results", END)

        return workflow.compile(name="log_analysis_agent")

    def _log_workflow_metrics(
        self,
        workflow_step: str,
        execution_time: float,
        success: bool,
        details: dict = None,
    ):
        """Log workflow step performance metrics to LangSmith."""
        try:
            current_run = get_current_run_tree()
            if current_run:
                ls_client.create_feedback(
                    run_id=current_run.id,
                    key="log_analysis_workflow_performance",
                    score=1.0 if success else 0.0,
                    value={
                        "workflow_step": workflow_step,
                        "execution_time": execution_time,
                        "success": success,
                        "details": details or {},
                        "agent_type": "log_analysis_workflow",
                    },
                )
        except Exception as e:
            print(f"Failed to log workflow metrics: {e}")

    def _log_security_analysis_results(self, analysis_result: dict):
        """Log security analysis findings to LangSmith."""
        try:
            current_run = get_current_run_tree()
            if current_run:
                assessment = analysis_result.get("overall_assessment", "UNKNOWN")
                abnormal_events = analysis_result.get("abnormal_events", [])
                total_events = analysis_result.get("total_events_analyzed", 0)

                # Calculate threat score
                threat_score = 0.0
                if assessment == "CRITICAL":
                    threat_score = 1.0
                elif assessment == "HIGH":
                    threat_score = 0.8
                elif assessment == "MEDIUM":
                    threat_score = 0.5
                elif assessment == "LOW":
                    threat_score = 0.2

                ls_client.create_feedback(
                    run_id=current_run.id,
                    key="security_analysis_results",
                    score=threat_score,
                    value={
                        "overall_assessment": assessment,
                        "abnormal_events_count": len(abnormal_events),
                        "total_events_analyzed": total_events,
                        "execution_time": analysis_result.get(
                            "execution_time_formatted", "Unknown"
                        ),
                        "iteration_count": analysis_result.get("iteration_count", 1),
                        "abnormal_events": abnormal_events[
                            :5
                        ],  # Limit to first 5 for logging
                    },
                )
        except Exception as e:
            print(f"Failed to log security analysis results: {e}")

    def _log_batch_analysis_metrics(
        self,
        total_files: int,
        successful: int,
        start_time: datetime,
        end_time: datetime,
    ):
        """Log batch analysis performance metrics."""
        try:
            current_run = get_current_run_tree()
            if current_run:
                duration = (end_time - start_time).total_seconds()
                success_rate = successful / total_files if total_files > 0 else 0

                ls_client.create_feedback(
                    run_id=current_run.id,
                    key="batch_analysis_performance",
                    score=success_rate,
                    value={
                        "total_files": total_files,
                        "successful_files": successful,
                        "failed_files": total_files - successful,
                        "success_rate": success_rate,
                        "duration_seconds": duration,
                        "files_per_minute": (
                            (total_files / duration) * 60 if duration > 0 else 0
                        ),
                    },
                )
        except Exception as e:
            print(f"Failed to log batch analysis metrics: {e}")

    @traceable(name="log_analysis_agent_full_workflow")
    def analyze(self, log_file: str) -> Dict:
        """
        Analyze a single log file

        Args:
            log_file: Path to the log file to analyze

        Returns:
            Dictionary containing the analysis result
        """
        state = self._initialize_state(log_file)
        result = self.workflow.invoke(state, config={"recursion_limit": 100})

        analysis_result = result.get("analysis_result", {})
        if analysis_result:
            self._log_security_analysis_results(analysis_result)

        return analysis_result

    @traceable(name="log_analysis_agent_batch_workflow")
    def analyze_batch(
        self, dataset_dir: str, skip_existing: bool = False
    ) -> List[Dict]:
        """
        Analyze all log files in a dataset directory

        Args:
            dataset_dir: Path to directory containing log files
            skip_existing: Whether to skip already analyzed files

        Returns:
            List of result dictionaries for each file
        """
        print("=" * 60)
        print("BATCH MODE: Analyzing all files in dataset")
        print("=" * 60 + "\n")

        files = self._find_dataset_files(dataset_dir)

        if not files:
            print("No JSON files found in dataset directory")
            return []

        print(f"Found {len(files)} files to analyze")
        if skip_existing:
            print("Skip mode enabled: Already analyzed files will be skipped")
        print()

        results = []
        batch_start = datetime.now()

        for idx, file_path in enumerate(files, 1):
            filename = os.path.basename(file_path)
            print(f"\n[{idx}/{len(files)}] Processing: {filename}")
            print("-" * 60)

            result = self._analyze_single_file(file_path, skip_existing)
            results.append(result)

            if result["success"]:
                print(f"Status: {result['message']}")
            else:
                print(f"Status: FAILED - {result['message']}")

        batch_end = datetime.now()

        successful = sum(1 for r in results if r["success"])
        self._log_batch_analysis_metrics(len(files), successful, batch_start, batch_end)

        self.result_manager.display_batch_summary(results, batch_start, batch_end)

        return results

    def _initialize_state(self, log_file: str) -> Dict:
        """Initialize the analysis state with default values"""
        return {
            "log_file": log_file,
            "raw_logs": "",
            "prepared_logs": "",
            "analysis_result": {},
            "messages": [],
            "agent_reasoning": "",
            "agent_observations": [],
            "iteration_count": 0,
            "critic_feedback": "",
            "iteration_history": [],
            "start_time": 0.0,
            "end_time": 0.0,
        }

    def _analyze_single_file(self, log_file: str, skip_existing: bool = False) -> Dict:
        """Analyze a single log file with error handling"""
        try:
            if skip_existing:
                existing = self.result_manager.get_existing_output(log_file)
                if existing:
                    return {
                        "success": True,
                        "log_file": log_file,
                        "message": "Skipped (already analyzed)",
                        "result": None,
                    }

            state = self._initialize_state(log_file)
            self.workflow.invoke(state, config={"recursion_limit": 100})

            return {
                "success": True,
                "log_file": log_file,
                "message": "Analysis completed",
                "result": state.get("analysis_result"),
            }

        except Exception as e:
            return {
                "success": False,
                "log_file": log_file,
                "message": f"Error: {str(e)}",
                "result": None,
            }

    def _find_dataset_files(self, dataset_dir: str) -> List[str]:
        """Find all JSON files in the dataset directory"""
        import glob

        if not os.path.exists(dataset_dir):
            print(f"Error: Dataset directory not found: {dataset_dir}")
            return []

        json_files = glob.glob(os.path.join(dataset_dir, "*.json"))
        return sorted(json_files)


class LogProcessor:
    """
    Handles log loading and preprocessing operations
    """

    def __init__(self, max_size: int = 30000, model_name: str = ""):
        """
        Initialize the log processor

        Args:
            max_size: Maximum character size before applying sampling
            model_name: Model name to adjust limits accordingly
        """
        if "gpt-oss" in model_name.lower():
            self.max_size = 5000  # Conservative limit for GPT-OSS models
            print(
                f"[INFO] Using reduced sampling size ({self.max_size}) for GPT-OSS model"
            )
        else:
            self.max_size = max_size

        self.model_name = model_name

    def _get_max_input_tokens(self, model_name: str) -> int:
        """
        Determine maximum input tokens based on model capabilities

        Args:
            model_name: Name of the model to determine token limits for

        Returns:
            Maximum input tokens for the model
        """
        model_lower = model_name.lower()

        # Gemini models: 300k tokens
        if "gemini" in model_lower:
            return 200_000

        # elif "gpt-5" in model_lower:
        #     return 80_000

        # Default for other models: 45k tokens
        else:
            return 45_000

    @traceable(name="log_processor_load_logs")
    def load_logs(self, state: AnalysisState) -> AnalysisState:
        """Load logs from file and initialize state"""
        filename = os.path.basename(state["log_file"])
        print(f"Loading logs from: {filename}")

        # Record start time
        state["start_time"] = time.time()
        start_time = time.time()

        try:
            with open(state["log_file"], "r", encoding="utf-8") as f:
                raw = f.read()
            success = True
        except Exception as e:
            print(f"Error reading file: {e}")
            raw = f"Error loading file: {e}"
            success = False

        execution_time = time.time() - start_time
        self._log_loading_metrics(filename, len(raw), execution_time, success)

        state["raw_logs"] = raw
        state["max_input_token"] = self._get_max_input_tokens(self.model_name)
        state["messages"] = []
        state["agent_reasoning"] = ""
        state["agent_observations"] = []
        state["iteration_count"] = 0
        state["critic_feedback"] = ""
        state["iteration_history"] = []
        state["end_time"] = 0.0

        return state

    @traceable(name="log_processor_preprocess_logs")
    def preprocess_logs(self, state: AnalysisState) -> AnalysisState:
        """Preprocess logs for analysis - token-based truncation based on model capabilities"""
        raw = state["raw_logs"]
        line_count = raw.count("\n")
        max_tokens = state["max_input_token"]
        print(
            f"Loaded {line_count} lines, {len(raw)} characters (max tokens: {max_tokens:,})"
        )

        start_time = time.time()

        # Truncate by tokens to keep context windows manageable
        truncated = truncate_to_tokens(raw, max_tokens)

        token_truncation_applied = len(truncated) < len(raw)

        # Prepare final text with minimal header
        state["prepared_logs"] = f"TOTAL LINES: {line_count}\n\n{truncated}"

        execution_time = time.time() - start_time
        self._log_preprocessing_metrics(
            line_count,
            len(raw),
            len(truncated),
            token_truncation_applied,
            execution_time,
        )

        return state

    def _log_loading_metrics(
        self, filename: str, file_size: int, execution_time: float, success: bool
    ):
        """Log file loading performance metrics."""
        try:
            current_run = get_current_run_tree()
            if current_run:
                ls_client.create_feedback(
                    run_id=current_run.id,
                    key="log_loading_performance",
                    score=1.0 if success else 0.0,
                    value={
                        "filename": filename,
                        "file_size_chars": file_size,
                        "execution_time": execution_time,
                        "success": success,
                    },
                )
        except Exception as e:
            print(f"Failed to log loading metrics: {e}")

    def _log_preprocessing_metrics(
        self,
        line_count: int,
        original_size: int,
        processed_size: int,
        sampling_applied: bool,
        execution_time: float,
    ):
        """Log preprocessing performance metrics."""
        try:
            current_run = get_current_run_tree()
            if current_run:
                ls_client.create_feedback(
                    run_id=current_run.id,
                    key="log_preprocessing_performance",
                    score=1.0,
                    value={
                        "line_count": line_count,
                        "original_size_chars": original_size,
                        "processed_size_chars": processed_size,
                        "sampling_applied": sampling_applied,
                        "size_reduction": (
                            (original_size - processed_size) / original_size
                            if original_size > 0
                            else 0
                        ),
                        "execution_time": execution_time,
                    },
                )
        except Exception as e:
            print(f"Failed to log preprocessing metrics: {e}")

    def _apply_sampling(self, raw: str) -> str:
        """Apply sampling strategy with line-aware boundaries"""
        lines = raw.split("\n")
        total_lines = len(lines)

        if total_lines <= 50:  # Small files, return as-is
            return raw

        # Take proportional samples but respect line boundaries
        first_lines = lines[: int(total_lines * 0.25)]  # First 25%
        middle_start = int(total_lines * 0.4)
        middle_end = int(total_lines * 0.6)
        middle_lines = lines[middle_start:middle_end]  # Middle 20%
        last_lines = lines[-int(total_lines * 0.25) :]  # Last 25%

        return f"""=== BEGINNING ({len(first_lines)} lines) ===
    {chr(10).join(first_lines)}

    === MIDDLE (lines {middle_start}-{middle_end}) ===
    {chr(10).join(middle_lines)}

    === END ({len(last_lines)} lines) ===
    {chr(10).join(last_lines)}"""


class ReactAnalyzer:
    """
    Handles ReAct agent analysis with iterative refinement
    Combines react_engine + criticism_engine logic
    """

    def __init__(self, llm, base_tools, max_iterations: int = 2):
        """
        Initialize the ReAct analyzer

        Args:
            llm: Language model instance
            base_tools: List of base tools for the agent
            max_iterations: Maximum refinement iterations
        """
        self.llm = llm
        self.base_tools = base_tools
        self.max_iterations = max_iterations

    @traceable(name="react_analyzer_analysis")
    def analyze(self, state: AnalysisState) -> AnalysisState:
        """Perform ReAct agent analysis with iterative refinement"""
        print("Starting ReAct agent analysis with iterative refinement...")

        start_time = time.time()

        # Create state-aware tools
        tools = self._create_state_aware_tools(state)

        # Create ReAct agent
        agent_executor = create_react_agent(
            self.llm, tools, name="react_agent_analysis"
        )

        # System context
        system_context = """You are Agent A, an autonomous cybersecurity analyst.

IMPORTANT CONTEXT - RAW LOGS AVAILABLE:
The complete raw logs are available for certain tools automatically.
When you call event_id_extractor_with_logs or timeline_builder_with_logs, 
you only need to provide the required parameters - the tools will automatically 
access the raw logs to perform their analysis.

"""

        try:
            # Iterative refinement loop
            for iteration in range(self.max_iterations):
                state["iteration_count"] = iteration
                print(f"\n{'='*60}")
                print(f"ITERATION {iteration + 1}/{self.max_iterations}")
                print(f"{'='*60}")

                # Prepare prompt with optional feedback
                messages = self._prepare_messages(state, iteration, system_context)

                # Run ReAct agent
                print(f"Running agent analysis...")
                result = agent_executor.invoke(
                    {"messages": messages}, config={"recursion_limit": 100}
                )
                state["messages"] = result["messages"]

                # Extract and process final analysis
                final_analysis = self._extract_final_analysis(state["messages"])

                # Calculate execution time
                state["end_time"] = time.time()
                execution_time = format_execution_time(
                    state["end_time"] - state["start_time"]
                )

                # Extract reasoning
                state["agent_reasoning"] = final_analysis.get("reasoning", "")

                # Format result
                state["analysis_result"] = self._format_analysis_result(
                    final_analysis,
                    execution_time,
                    iteration + 1,
                    state["agent_reasoning"],
                )

                # Run self-critic review
                print("Running self-critic review...")
                original_analysis = state["analysis_result"].copy()
                critic_result = self._critic_review(state)

                # Store iteration in history
                state["iteration_history"].append(
                    {
                        "iteration": iteration + 1,
                        "original_analysis": original_analysis,
                        "critic_evaluation": {
                            "quality_acceptable": critic_result["quality_acceptable"],
                            "issues": critic_result["issues"],
                            "feedback": critic_result["feedback"],
                        },
                        "corrected_analysis": critic_result["corrected_analysis"],
                    }
                )

                # Use corrected analysis
                corrected = critic_result["corrected_analysis"]
                corrected["execution_time_seconds"] = original_analysis.get(
                    "execution_time_seconds", 0
                )
                corrected["execution_time_formatted"] = original_analysis.get(
                    "execution_time_formatted", "Unknown"
                )
                corrected["iteration_count"] = iteration + 1
                state["analysis_result"] = corrected

                # Check if refinement is needed
                if critic_result["quality_acceptable"]:
                    print(
                        f"✓ Quality acceptable - stopping at iteration {iteration + 1}"
                    )
                    break
                elif iteration < self.max_iterations - 1:
                    print(
                        f"✗ Quality needs improvement - proceeding to iteration {iteration + 2}"
                    )
                    state["critic_feedback"] = critic_result["feedback"]
                else:
                    print(f"✗ Max iterations reached - using current analysis")

            print(
                f"\nAnalysis complete after {state['iteration_count'] + 1} iteration(s)"
            )
            print(f"Total messages: {len(state['messages'])}")

        except Exception as e:
            print(f"Error in analysis: {e}")
            import traceback

            traceback.print_exc()
            state["end_time"] = time.time()
            execution_time = format_execution_time(
                state["end_time"] - state["start_time"]
            )

            state["analysis_result"] = {
                "overall_assessment": "ERROR",
                "total_events_analyzed": 0,
                "execution_time_seconds": execution_time["total_seconds"],
                "execution_time_formatted": execution_time["formatted_time"],
                "analysis_summary": f"Analysis failed: {e}",
                "agent_reasoning": "",
                "abnormal_event_ids": [],
                "abnormal_events": [],
                "iteration_count": state.get("iteration_count", 0),
            }

        return state

    def _create_state_aware_tools(self, state: AnalysisState):
        """Create state-aware versions of tools that need raw logs"""

        # Create state-aware event_id_extractor
        @tool
        def event_id_extractor_with_logs(suspected_event_id: str) -> dict:
            """Validates and corrects Windows Event IDs identified in log analysis."""
            from .tools.event_id_extractor_tool import _event_id_extractor_tool

            return _event_id_extractor_tool.run(
                {
                    "suspected_event_id": suspected_event_id,
                    "raw_logs": state["raw_logs"],
                }
            )

        # Create state-aware timeline_builder
        @tool
        def timeline_builder_with_logs(
            pivot_entity: str, pivot_type: str, time_window_minutes: int = 5
        ) -> dict:
            """Build a focused timeline around suspicious events to understand attack sequences.

            Use this when you suspect coordinated activity or want to understand what happened
            before and after a suspicious event. Analyzes the sequence of events to identify patterns.

            Args:
                pivot_entity: The entity to build timeline around (e.g., "powershell.exe", "admin", "192.168.1.100")
                pivot_type: Type of entity - "user", "process", "ip", "file", "computer", "event_id", or "registry"
                time_window_minutes: Minutes before and after pivot events to include (default: 5)

            Returns:
                Timeline analysis showing events before and after the pivot, helping identify attack sequences.
            """
            from .tools.timeline_builder_tool import _timeline_builder_tool

            return _timeline_builder_tool.run(
                {
                    "pivot_entity": pivot_entity,
                    "pivot_type": pivot_type,
                    "time_window_minutes": time_window_minutes,
                    "raw_logs": state["raw_logs"],
                }
            )

        # Replace base tools with state-aware versions
        tools = [
            t
            for t in self.base_tools
            if t.name not in ["event_id_extractor", "timeline_builder"]
        ]
        tools.append(event_id_extractor_with_logs)
        tools.append(timeline_builder_with_logs)

        return tools

    def _prepare_messages(
        self, state: AnalysisState, iteration: int, system_context: str
    ):
        """Prepare messages for the ReAct agent"""
        if iteration == 0:
            # First iteration - no feedback
            critic_feedback_section = ""
            full_prompt = system_context + ANALYSIS_PROMPT.format(
                logs=state["prepared_logs"],
                critic_feedback_section=critic_feedback_section,
            )
            messages = [HumanMessage(content=full_prompt)]
        else:
            # Subsequent iterations - include feedback and preserve messages
            critic_feedback_section = CRITIC_FEEDBACK_TEMPLATE.format(
                iteration=iteration + 1, feedback=state["critic_feedback"]
            )
            # ONLY COPY LANGCHAIN MESSAGE OBJECTS, NOT DICTS
            messages = [msg for msg in state["messages"] if not isinstance(msg, dict)]
            messages.append(HumanMessage(content=critic_feedback_section))

        return messages

    def _extract_final_analysis(self, messages):
        """Extract the final analysis from agent messages"""
        final_message = None
        for msg in reversed(messages):
            if (
                hasattr(msg, "__class__")
                and msg.__class__.__name__ == "AIMessage"
                and hasattr(msg, "content")
                and msg.content
                and (not hasattr(msg, "tool_calls") or not msg.tool_calls)
            ):
                final_message = msg.content
                break

        if not final_message:
            raise Exception("No final analysis message found")

        return self._parse_agent_output(final_message)

    def _parse_agent_output(self, content: str) -> dict:
        """Parse agent's final output"""
        try:
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0].strip()
            else:
                json_str = content.strip()

            return json.loads(json_str)
        except Exception as e:
            print(f"Failed to parse agent output: {e}")
            return {
                "overall_assessment": "UNKNOWN",
                "total_events_analyzed": 0,
                "analysis_summary": content[:500],
                "reasoning": "",
                "abnormal_event_ids": [],
                "abnormal_events": [],
            }

    def _format_analysis_result(
        self, final_analysis, execution_time, iteration_count, agent_reasoning
    ):
        """Format the analysis result into the expected structure"""
        abnormal_events = []
        for event in final_analysis.get("abnormal_events", []):
            event_with_tools = {
                "event_id": event.get("event_id", ""),
                "event_description": event.get("event_description", ""),
                "why_abnormal": event.get("why_abnormal", ""),
                "severity": event.get("severity", ""),
                "indicators": event.get("indicators", []),
                "potential_threat": event.get("potential_threat", ""),
                "attack_category": event.get("attack_category", ""),
                "tool_enrichment": event.get("tool_enrichment", {}),
            }
            abnormal_events.append(event_with_tools)

        return {
            "overall_assessment": final_analysis.get("overall_assessment", "UNKNOWN"),
            "total_events_analyzed": final_analysis.get("total_events_analyzed", 0),
            "execution_time_seconds": execution_time["total_seconds"],
            "execution_time_formatted": execution_time["formatted_time"],
            "analysis_summary": final_analysis.get("analysis_summary", ""),
            "agent_reasoning": agent_reasoning,
            "abnormal_event_ids": final_analysis.get("abnormal_event_ids", []),
            "abnormal_events": abnormal_events,
            "iteration_count": iteration_count,
        }

    # ========== CRITIC ENGINE METHODS ==========

    def _critic_review(self, state: dict) -> dict:
        """Run self-critic review with quality evaluation"""
        critic_input = SELF_CRITIC_PROMPT.format(
            final_json=json.dumps(state["analysis_result"], indent=2),
            messages="\n".join(
                [str(m.content) for m in state["messages"] if hasattr(m, "content")]
            ),
            logs=state["prepared_logs"],
        )

        resp = self.llm.invoke(critic_input)
        full_response = resp.content

        try:
            # Parse critic response
            quality_acceptable, issues, feedback, corrected_json = (
                self._parse_critic_response(full_response)
            )

            return {
                "quality_acceptable": quality_acceptable,
                "issues": issues,
                "feedback": feedback,
                "corrected_analysis": corrected_json,
                "full_response": full_response,
            }
        except Exception as e:
            print(f"[Critic] Failed to parse review: {e}")
            # If critic fails, accept current analysis
            return {
                "quality_acceptable": True,
                "issues": [],
                "feedback": "",
                "corrected_analysis": state["analysis_result"],
                "full_response": full_response,
            }

    def _parse_critic_response(self, content: str) -> tuple:
        """Parse critic response and evaluate quality"""

        # Extract sections
        issues_section = ""
        feedback_section = ""

        if "## ISSUES FOUND" in content:
            parts = content.split("## ISSUES FOUND")
            if len(parts) > 1:
                issues_part = parts[1].split("##")[0].strip()
                issues_section = issues_part

        if "## FEEDBACK FOR AGENT" in content:
            parts = content.split("## FEEDBACK FOR AGENT")
            if len(parts) > 1:
                feedback_part = parts[1].split("##")[0].strip()
                feedback_section = feedback_part

        # Extract corrected JSON
        if "```json" in content:
            json_str = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            json_str = content.split("```")[1].split("```")[0].strip()
        else:
            json_str = "{}"

        corrected_json = json.loads(json_str)

        # Evaluate quality based on issues
        issues = self._extract_issues(issues_section)
        quality_acceptable = self._evaluate_quality(issues, issues_section)

        return quality_acceptable, issues, feedback_section, corrected_json

    def _extract_issues(self, issues_text: str) -> list:
        """Extract structured issues from text"""
        issues = []

        # Check for "None" or "no issues"
        if (
            "none" in issues_text.lower()
            and "analysis is acceptable" in issues_text.lower()
        ):
            return issues

        # Extract issue types
        issue_types = {
            "MISSING_EVENT_IDS": "missing_event_ids",
            "SEVERITY_MISMATCH": "severity_mismatch",
            "IGNORED_TOOLS": "ignored_tool_results",
            "INCOMPLETE_EVENTS": "incomplete_abnormal_events",
            "EVENT_ID_FORMAT": "event_id_format",
            "SCHEMA_ISSUES": "schema_issues",
            "UNDECODED_COMMANDS": "undecoded_commands",
        }

        for keyword, issue_type in issue_types.items():
            if keyword in issues_text:
                issues.append({"type": issue_type, "text": issues_text})

        return issues

    def _evaluate_quality(self, issues: list, issues_text: str) -> bool:
        """Evaluate if quality is acceptable"""
        # If no issues found
        if not issues:
            return True

        # Critical issue types that trigger iteration
        critical_types = {
            "missing_event_ids",
            "severity_mismatch",
            "ignored_tool_results",
            "incomplete_abnormal_events",
            "undecoded_commands",
        }

        # Count critical issues
        critical_count = sum(1 for issue in issues if issue["type"] in critical_types)

        # Quality threshold: max 1 critical issue is acceptable
        if critical_count >= 2:
            return False

        # Additional check: if issues_text indicates major problems
        if any(
            word in issues_text.lower() for word in ["critical", "major", "serious"]
        ):
            return False

        return True


class ResultManager:
    """
    Handles saving results to disk and displaying to console
    """

    def __init__(self, output_root: Path):
        """
        Initialize the result manager

        Args:
            output_root: Root directory for saving outputs
        """
        self.output_root = output_root

    @traceable(name="result_manager_save_results")
    def save_results(self, state: AnalysisState) -> AnalysisState:
        """Save analysis results and messages to files"""
        input_name = os.path.splitext(os.path.basename(state["log_file"]))[0]
        analysis_dir = self.output_root / input_name

        analysis_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        start_time = time.time()
        success = True

        try:
            # Save main analysis result
            out_file = analysis_dir / f"analysis_{ts}.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(state["analysis_result"], f, indent=2)

            # Save iteration history
            history_file = analysis_dir / f"iterations_{ts}.json"
            with open(history_file, "w", encoding="utf-8") as f:
                json.dump(state.get("iteration_history", []), f, indent=2)

            # Save messages history
            messages_file = analysis_dir / f"messages_{ts}.json"
            serializable_messages = self._serialize_messages(state.get("messages", []))
            with open(messages_file, "w", encoding="utf-8") as f:
                json.dump(serializable_messages, f, indent=2)

        except Exception as e:
            print(f"Error saving results: {e}")
            success = False

        execution_time = time.time() - start_time
        self._log_save_metrics(input_name, execution_time, success)

        return state

    def _log_save_metrics(self, input_name: str, execution_time: float, success: bool):
        """Log file saving performance metrics."""
        try:
            current_run = get_current_run_tree()
            if current_run:
                ls_client.create_feedback(
                    run_id=current_run.id,
                    key="result_save_performance",
                    score=1.0 if success else 0.0,
                    value={
                        "input_name": input_name,
                        "execution_time": execution_time,
                        "success": success,
                    },
                )
        except Exception as e:
            print(f"Failed to log save metrics: {e}")

    @traceable(name="result_manager_display_results")
    def display_results(self, state: AnalysisState) -> AnalysisState:
        """Display formatted analysis results"""
        result = state["analysis_result"]
        assessment = result.get("overall_assessment", "UNKNOWN")
        execution_time = result.get("execution_time_formatted", "Unknown")
        abnormal_events = result.get("abnormal_events", [])
        iteration_count = result.get("iteration_count", 1)

        print("\n" + "=" * 60)
        print("ANALYSIS COMPLETE")
        print("=" * 60)

        print(f"ASSESSMENT: {assessment}")
        print(f"ITERATIONS: {iteration_count}")
        print(f"EXECUTION TIME: {execution_time}")
        print(f"EVENTS ANALYZED: {result.get('total_events_analyzed', 'Unknown')}")

        # Tools Used
        tools_used = self._extract_tools_used(state.get("messages", []))

        if tools_used:
            print(f"TOOLS USED: {len(tools_used)} tools")
            print(f"  Types: {', '.join(sorted(tools_used))}")
        else:
            print("TOOLS USED: None")

        # Abnormal Events
        if abnormal_events:
            print(f"\nABNORMAL EVENTS: {len(abnormal_events)}")
            for event in abnormal_events:
                severity = event.get("severity", "UNKNOWN")
                event_id = event.get("event_id", "N/A")
                print(f"  EventID {event_id} [{severity}]")
        else:
            print("\nNO ABNORMAL EVENTS")

        print("=" * 60)

        return state

    def display_batch_summary(
        self, results: List[Dict], start_time: datetime, end_time: datetime
    ):
        """Print summary of batch processing results"""
        total = len(results)
        successful = sum(1 for r in results if r["success"])
        skipped = sum(1 for r in results if "Skipped" in r["message"])
        failed = total - successful

        duration = (end_time - start_time).total_seconds()

        print("\n" + "=" * 60)
        print("BATCH ANALYSIS SUMMARY")
        print("=" * 60)
        print(f"Total files: {total}")
        print(f"Successful: {successful}")
        print(f"Skipped: {skipped}")
        print(f"Failed: {failed}")
        print(f"Total time: {duration:.2f} seconds ({duration/60:.2f} minutes)")

        if failed > 0:
            print(f"\nFailed files:")
            for r in results:
                if not r["success"]:
                    filename = os.path.basename(r["log_file"])
                    print(f"  - {filename}: {r['message']}")

        print("=" * 60 + "\n")

    def get_existing_output(self, log_file: str) -> Optional[str]:
        """Get the output file path for a given log file if it exists"""
        import glob

        input_name = os.path.splitext(os.path.basename(log_file))[0]
        analysis_dir = self.output_root / input_name

        if analysis_dir.exists():
            existing_files = list(analysis_dir.glob("analysis_*.json"))
            if existing_files:
                return str(existing_files[0])
        return None

    def _serialize_messages(self, messages) -> List[dict]:
        """Serialize messages for JSON storage"""
        serializable_messages = []
        for msg in messages:
            if isinstance(msg, dict):
                serializable_messages.append(msg)
            else:
                msg_dict = {
                    "type": msg.__class__.__name__,
                    "content": msg.content if hasattr(msg, "content") else str(msg),
                }
                if hasattr(msg, "tool_calls") and msg.tool_calls:
                    msg_dict["tool_calls"] = [
                        {"name": tc.get("name", ""), "args": tc.get("args", {})}
                        for tc in msg.tool_calls
                    ]
                serializable_messages.append(msg_dict)

        return serializable_messages

    def _extract_tools_used(self, messages) -> set:
        """Extract set of tool names used during analysis"""
        tools_used = set()
        for msg in messages:
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                for tc in msg.tool_calls:
                    tool_name = tc.get("name", "")
                    if tool_name:
                        tools_used.add(tool_name)
        return tools_used
