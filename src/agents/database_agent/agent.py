"""
Database Agent - A specialized ReAct agent for MITRE ATT&CK technique retrieval

This agent provides semantic search capabilities over the MITRE ATT&CK knowledge base
with support for filtered searches by tactics, platforms, and other metadata.
"""

import os
import json
import sys
import time
from typing import List, Dict, Any, Optional, Literal
from pathlib import Path

# LangGraph and LangChain imports
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, AIMessage
from langchain.chat_models import init_chat_model
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_text_splitters import TokenTextSplitter
from langgraph.prebuilt import create_react_agent

# LangSmith imports
from langsmith import traceable, Client, get_current_run_tree

# Import prompts from the separate file
from src.agents.database_agent.prompts import DATABASE_AGENT_SYSTEM_PROMPT

# Import the cyber knowledge base
try:
    from src.knowledge_base.cyber_knowledge_base import CyberKnowledgeBase
except Exception as e:
    print(
        f"[WARNING] Could not import CyberKnowledgeBase. Please adjust import paths. {e}"
    )
    sys.exit(1)

ls_client = Client(api_key=os.getenv("LANGSMITH_API_KEY"))


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """
    Truncate text to a maximum number of tokens using LangChain's TokenTextSplitter.

    Args:
        text: The text to truncate
        max_tokens: Maximum number of tokens

    Returns:
        Truncated text within the token limit
    """
    if not text:
        return ""

    # Clean the text by replacing newlines with spaces
    cleaned_text = text.replace("\n", " ")

    # Use TokenTextSplitter to split by tokens
    splitter = TokenTextSplitter(
        encoding_name="o200k_base", chunk_size=max_tokens, chunk_overlap=0
    )

    chunks = splitter.split_text(cleaned_text)
    return chunks[0] if chunks else ""


class DatabaseAgent:
    """
    A specialized ReAct agent for MITRE ATT&CK technique retrieval and search.

    This agent provides intelligent search capabilities over the MITRE ATT&CK knowledge base,
    including semantic search, filtered search, and multi-query search with RRF fusion.
    """

    def __init__(
        self,
        kb_path: str = "./cyber_knowledge_base",
        llm_client: BaseChatModel = None,
    ):
        """
        Initialize the Database Agent.

        Args:
            kb_path: Path to the cyber knowledge base directory
            llm_client: LLM model to use for the agent
        """
        self.kb_path = kb_path
        self.kb = self._init_knowledge_base()

        if llm_client:
            self.llm = llm_client
        else:
            self.llm = init_chat_model(
                "google_genai:gemini-2.0-flash",
                temperature=0.1,
            )
            print(
                f"[INFO] Database Agent: Using default LLM model: google_genai:gemini-2.0-flash"
            )
        # Create tools
        self.tools = self._create_tools()

        # Create ReAct agent
        self.agent = self._create_react_agent()

    @traceable(name="database_agent_init_kb")
    def _init_knowledge_base(self) -> CyberKnowledgeBase:
        """Initialize and load the cyber knowledge base."""
        kb = CyberKnowledgeBase()

        if kb.load_knowledge_base(self.kb_path):
            print("[SUCCESS] Database Agent: Loaded existing knowledge base")
            return kb
        else:
            print(
                f"[ERROR] Database Agent: Could not load knowledge base from {self.kb_path}"
            )
            print("Please ensure the knowledge base is built and available.")
            raise RuntimeError("Knowledge base not available")

    @traceable(name="database_agent_format_results")
    def _format_results_as_json(self, results) -> List[Dict[str, Any]]:
        """Format search results as structured JSON."""
        output = []
        for doc in results:
            technique_info = {
                "attack_id": doc.metadata.get("attack_id", "Unknown"),
                "name": doc.metadata.get("name", "Unknown"),
                "tactics": [
                    t.strip()
                    for t in doc.metadata.get("tactics", "").split(",")
                    if t.strip()
                ],
                "platforms": [
                    p.strip()
                    for p in doc.metadata.get("platforms", "").split(",")
                    if p.strip()
                ],
                "description": truncate_to_tokens(doc.page_content, 300),
                "relevance_score": doc.metadata.get("relevance_score", None),
                "rrf_score": doc.metadata.get("rrf_score", None),
                "mitigation_count": doc.metadata.get("mitigation_count", 0),
                # "mitigations": truncate_to_tokens(
                #     doc.metadata.get("mitigations", ""), 50
                # ),
            }
            output.append(technique_info)
        return output

    def _log_search_metrics(
        self,
        search_type: str,
        query: str,
        results_count: int,
        execution_time: float,
        success: bool,
    ):
        """Log search performance metrics to LangSmith."""
        try:
            current_run = get_current_run_tree()
            if current_run:
                ls_client.create_feedback(
                    run_id=current_run.id,
                    key="database_search_performance",
                    score=1.0 if success else 0.0,
                    value={
                        "search_type": search_type,
                        "query": query,
                        "results_count": results_count,
                        "execution_time": execution_time,
                        "success": success,
                    },
                )
        except Exception as e:
            print(f"Failed to log search metrics: {e}")

    def _log_agent_performance(
        self, query: str, message_count: int, execution_time: float, success: bool
    ):
        """Log overall agent performance metrics."""
        try:
            current_run = get_current_run_tree()
            if current_run:
                ls_client.create_feedback(
                    run_id=current_run.id,
                    key="database_agent_performance",
                    score=1.0 if success else 0.0,
                    value={
                        "query": query,
                        "message_count": message_count,
                        "execution_time": execution_time,
                        "success": success,
                        "agent_type": "database_search",
                    },
                )
        except Exception as e:
            print(f"Failed to log agent metrics: {e}")

    def _create_tools(self):
        """Create the search tools for the Database Agent."""

        @tool
        @traceable(name="database_search_techniques")
        def search_techniques(query: str, top_k: int = 5) -> str:
            """
            Search for MITRE ATT&CK techniques using semantic search.

            Args:
                query: Search query string
                top_k: Number of results to return (default: 5, max: 20)

            Returns:
                JSON string with search results containing technique details
            """
            start_time = time.time()
            try:
                # Limit top_k for performance
                top_k = min(max(top_k, 1), 20)  # Ensure top_k is between 1 and 20

                # Single query search
                results = self.kb.search(query, top_k=top_k)
                techniques = self._format_results_as_json(results)

                execution_time = time.time() - start_time
                self._log_search_metrics(
                    "single_query", query, len(techniques), execution_time, True
                )

                return json.dumps(
                    {
                        "search_type": "single_query",
                        "query": query,
                        "techniques": techniques,
                        "total_results": len(techniques),
                    },
                    indent=2,
                )

            except Exception as e:
                execution_time = time.time() - start_time
                self._log_search_metrics(
                    "single_query", query, 0, execution_time, False
                )

                return json.dumps(
                    {
                        "error": str(e),
                        "techniques": [],
                        "message": "Error occurred during search",
                    },
                    indent=2,
                )

        @tool
        @traceable(name="database_search_techniques_filtered")
        def search_techniques_filtered(
            query: str,
            top_k: int = 5,
            filter_tactics: Optional[List[str]] = None,
            filter_platforms: Optional[List[str]] = None,
        ) -> str:
            """
            Search for MITRE ATT&CK techniques with metadata filters.

            Args:
                query: Search query string
                top_k: Number of results to return (default: 5, max: 20)
                filter_tactics: Filter by specific tactics (e.g., ['defense-evasion', 'privilege-escalation'])
                filter_platforms: Filter by platforms (e.g., ['Windows', 'Linux'])

            Returns:
                JSON string with filtered search results

            Examples of tactics: initial-access, execution, persistence, privilege-escalation,
            defense-evasion, credential-access, discovery, lateral-movement, collection,
            command-and-control, exfiltration, impact

            Examples of platforms: Windows, macOS, Linux, AWS, Azure, GCP, SaaS, Network,
            Containers, Android, iOS
            """
            start_time = time.time()
            try:
                # Limit top_k for performance
                top_k = min(max(top_k, 1), 20)

                # Single query search with filters
                results = self.kb.search(
                    query,
                    top_k=top_k,
                    filter_tactics=filter_tactics,
                    filter_platforms=filter_platforms,
                )
                techniques = self._format_results_as_json(results)

                execution_time = time.time() - start_time
                self._log_search_metrics(
                    "filtered_query", query, len(techniques), execution_time, True
                )

                return json.dumps(
                    {
                        "search_type": "single_query_filtered",
                        "query": query,
                        "filters": {
                            "tactics": filter_tactics,
                            "platforms": filter_platforms,
                        },
                        "techniques": techniques,
                        "total_results": len(techniques),
                    },
                    indent=2,
                )

            except Exception as e:
                execution_time = time.time() - start_time
                self._log_search_metrics(
                    "filtered_query", query, 0, execution_time, False
                )

                return json.dumps(
                    {
                        "error": str(e),
                        "techniques": [],
                        "message": "Error occurred during filtered search",
                    },
                    indent=2,
                )

        # return [search_techniques, search_techniques_filtered]
        return [search_techniques]

    def _create_react_agent(self):
        """Create the ReAct agent with the search tools using the prompt from prompts.py."""
        return create_react_agent(
            model=self.llm,
            tools=self.tools,
            prompt=DATABASE_AGENT_SYSTEM_PROMPT,
            name="database_agent",
        )

    @traceable(name="database_agent_search")
    def search(self, query: str, **kwargs) -> Dict[str, Any]:
        """
        Search for techniques using the agent's capabilities.

        Args:
            query: The search query or question
            **kwargs: Additional parameters passed to the agent

        Returns:
            Dictionary with the agent's response
        """
        start_time = time.time()
        try:
            messages = [HumanMessage(content=query)]
            response = self.agent.invoke({"messages": messages}, **kwargs)

            execution_time = time.time() - start_time
            self._log_agent_performance(
                query, len(response.get("messages", [])), execution_time, True
            )

            return {
                "success": True,
                "messages": response["messages"],
                "final_response": (
                    response["messages"][-1].content if response["messages"] else ""
                ),
            }
        except Exception as e:
            execution_time = time.time() - start_time
            self._log_agent_performance(query, 0, execution_time, False)

            return {
                "success": False,
                "error": str(e),
                "messages": [],
                "final_response": f"Error during search: {str(e)}",
            }

    @traceable(name="database_agent_stream_search")
    def stream_search(self, query: str, **kwargs):
        """
        Stream the agent's search process for real-time feedback.

        Args:
            query: The search query or question
            **kwargs: Additional parameters passed to the agent

        Yields:
            Streaming responses from the agent
        """
        try:
            messages = [HumanMessage(content=query)]
            for chunk in self.agent.stream({"messages": messages}, **kwargs):
                yield chunk
        except Exception as e:
            yield {"error": str(e)}


@traceable(name="database_agent_test")
def test_database_agent():
    """Test function to demonstrate Database Agent capabilities."""
    print("Testing Database Agent...")

    # Initialize agent
    try:
        agent = DatabaseAgent()
        print("Database Agent initialized successfully")
    except Exception as e:
        print(f"Failed to initialize Database Agent: {e}")
        return

    # Test queries
    test_queries = [
        "Find techniques related to credential dumping and LSASS memory access",
        "What are Windows-specific privilege escalation techniques?",
        "Search for defense evasion techniques that work on Linux platforms",
        "Find lateral movement techniques involving SMB or WMI",
        "What techniques are used for persistence on macOS systems?",
    ]

    for i, query in enumerate(test_queries, 1):
        print(f"\n--- Test Query {i} ---")
        print(f"Query: {query}")
        print("-" * 50)

        # Test regular search
        result = agent.search(query)
        if result["success"]:
            print("Search completed successfully")
            # Print last AI message (the summary)
            for msg in reversed(result["messages"]):
                if isinstance(msg, AIMessage) and not hasattr(msg, "tool_calls"):
                    print(f"Response: {msg.content[:300]}...")
                    break
        else:
            print(f"Search failed: {result['error']}")


if __name__ == "__main__":
    test_database_agent()
