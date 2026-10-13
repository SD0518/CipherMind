from typing import TypedDict, List, Dict, Any
from langchain_core.messages import BaseMessage


class AnalysisState(TypedDict):
    # Core data fields
    log_file: str
    raw_logs: str
    prepared_logs: str
    analysis_result: dict

    # Token configuration
    max_input_token: int  # Maximum input tokens based on model capabilities

    # Timing fields
    start_time: float
    end_time: float

    # ReAct agent conversation tracking
    messages: List[BaseMessage]  # Tracks agent thoughts, tool calls, and tool results

    # Iterative refinement fields
    iteration_count: int  # Current iteration: 0, 1, or 2
    critic_feedback: str  # Feedback from critic for next iteration
    iteration_history: List[dict]  # Track all iterations for debugging/analysis

    # Backwards compatibility
    agent_reasoning: str
    agent_observations: List
