"""
React Agent for Cyber Knowledge Base

This script creates a ReAct agent using LangGraph that can use the CyberKnowledgeBase
search method as a tool to retrieve MITRE ATT&CK techniques.
"""

import os
import sys
import json
from typing import List, Dict, Any, Union, Optional
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from langgraph.prebuilt import create_react_agent
from langchain.chat_models import init_chat_model
from langchain_core.language_models.chat_models import BaseChatModel

# Import local modules
from src.knowledge_base.cyber_knowledge_base import CyberKnowledgeBase


# Initialize the knowledge base
def init_knowledge_base(
    persist_dir: str = "./cyber_knowledge_base",
) -> CyberKnowledgeBase:
    """Initialize and load the cyber knowledge base"""
    kb = CyberKnowledgeBase()

    # Try to load existing knowledge base
    if kb.load_knowledge_base(persist_dir):
        print("[SUCCESS] Loaded existing knowledge base")
        return kb
    else:
        print("[WARNING] Could not load knowledge base, please build it first")
        print("Run: python src/scripts/build_cyber_database.py")
        sys.exit(1)


def _format_results_as_json(results) -> List[Dict[str, Any]]:
    """Format search results as structured JSON"""
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
            "description": (
                doc.page_content.split("Description: ")[-1]
                if "Description: " in doc.page_content
                else doc.page_content
            ),
            "relevance_score": doc.metadata.get(
                "relevance_score", None
            ),  # From reranking
        }
        output.append(technique_info)

    return output


def create_agent(llm_client: BaseChatModel, kb: CyberKnowledgeBase):
    """Create a ReAct agent with LangGraph"""

    # Define the tools bound to the provided knowledge base
    @tool
    def search_techniques(
        queries: Union[str, List[str]],
        top_k: int = 5,
        rerank_query: Optional[str] = None,
    ) -> str:
        """
        Search for MITRE ATT&CK techniques using the knowledge base.

        This tool searches a vector database containing MITRE ATT&CK technique descriptions,
        including their tactics, platforms, and detailed behavioral information. Each technique
        in the database has its full description embedded for semantic similarity search.

        Args:
            queries: Single search query string OR list of query strings.
            rerank_query: Optional tag echoed in the output for transparency.
            top_k: Number of results to return per query (default: 10)

        Returns:
            JSON string with results grouped per query. Each group contains:
            - query: The original query string
            - techniques: List of technique objects (attack_id, name, tactics, platforms, description, relevance_score)
            - total_results: Number of techniques in this group
        """
        try:
            # Convert single query to list for uniform processing
            if isinstance(queries, str):
                queries = [queries]

            # Run a normal search once per query and keep results associated with that query
            results_by_query: List[Dict[str, Any]] = []
            for i, q in enumerate(queries, 1):
                print(f"[INFO] Query {i}/{len(queries)}: '{q}'")
                per_query_results = kb.search(q, top_k=top_k)
                techniques = _format_results_as_json(per_query_results)
                results_by_query.append(
                    {
                        "query": q,
                        "techniques": techniques,
                        "total_results": len(techniques),
                    }
                )

            # If all queries returned no results
            if all(len(group["techniques"]) == 0 for group in results_by_query):
                return json.dumps(
                    {
                        "results_by_query": results_by_query,
                        "message": "No techniques found matching the provided queries.",
                    },
                    indent=2,
                )

            return json.dumps(
                {
                    "results_by_query": results_by_query,
                    "queries_used": queries,
                    "rerank_query": rerank_query,
                },
                indent=2,
            )

        except Exception as e:
            return json.dumps(
                {
                    "error": str(e),
                    "techniques": [],
                    "message": "Error occurred during search",
                },
                indent=2,
            )

    tools = [search_techniques]

    # Define the system prompt for the agent
    system_prompt = """
You are a cybersecurity analyst assistant that helps answer questions about MITRE ATT&CK techniques.
    
You have access to a knowledge base of MITRE ATT&CK techniques that you can search.
Use the search_techniques tool to find relevant techniques based on the user's query.
"""

    # Get the LLM from the client
    llm = llm_client

    # Create the React agent
    agent_runnable = create_react_agent(llm, tools, prompt=system_prompt)

    return agent_runnable


def run_test_queries(agent):
    """Run the agent with some test queries"""

    # Test queries
    test_queries = [
        "What techniques are used for credential dumping?",
        "How do attackers use process injection for defense evasion?",
        "What are common persistence techniques on Windows systems?",
    ]

    # Run the agent with test queries
    for i, query in enumerate(test_queries, 1):
        print(f"\n\n===== Test Query {i}: '{query}' =====\n")

        # Create the input state
        state = {"messages": [HumanMessage(content=query)]}

        # Run the agent
        result = agent.invoke(state)

        # Print all intermediate messages
        print("[TRACE] Conversation messages:")
        for message in result["messages"]:
            if isinstance(message, HumanMessage):
                print(f"- [Human] {message.content}")
            elif isinstance(message, AIMessage):
                agent_name = getattr(message, "name", None) or "agent"
                print(f"- [Agent:{agent_name}] {message.content}")
                if "function_call" in message.additional_kwargs:
                    fc = message.additional_kwargs["function_call"]
                    print(f"  [ToolCall] {fc.get('name')}: {fc.get('arguments')}")
            elif isinstance(message, ToolMessage):
                tool_name = getattr(message, "name", None) or "tool"
                print(f"- [Tool:{tool_name}] {message.content}")


def interactive_mode(agent):
    """Run the agent in interactive mode"""
    print("\n\n===== Interactive Mode =====")
    print("Type 'exit' or 'quit' to end the session\n")

    # Keep track of conversation history
    messages = []

    while True:
        # Get user input
        user_input = input("\nYou: ")

        # Check if user wants to exit
        if user_input.lower() in ["exit", "quit"]:
            print("Exiting interactive mode...")
            break

        # Add user message to history
        messages.append(HumanMessage(content=user_input))

        # Create the input state
        state = {"messages": messages.copy()}

        # Run the agent
        try:
            result = agent.invoke(state)

            # Update conversation history with agent's response
            messages = result["messages"]

            # Print the agent's response
            for message in messages:
                if isinstance(message, AIMessage):
                    print("\n" + "=" * 50)
                    print(f"\nAgent: {message.content}")
                    if "function_call" in message.additional_kwargs:
                        print(
                            "Function call:",
                            message.additional_kwargs["function_call"]["name"],
                        )
                        print(
                            "Arguments:",
                            message.additional_kwargs["function_call"]["arguments"],
                        )

                print("-" * 50)

                if isinstance(message, ToolMessage):
                    print("Tool output:", message.content)

        except Exception as e:
            print(f"Error: {str(e)}")


def main():
    """Main function to run the agent"""
    global kb

    # Initialize the knowledge base
    kb_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "cyber_knowledge_base",
    )
    kb = init_knowledge_base(kb_path)

    # Print KB stats
    stats = kb.get_stats()
    print(
        f"Knowledge base loaded with {stats.get('total_techniques', 'unknown')} techniques"
    )

    # Initialize the LLM client (using environment variables)
    llm_client = init_chat_model("google_genai:gemini-2.0-flash", temperature=0.2)

    # Create the agent
    agent = create_agent(llm_client, kb)

    # Parse command line arguments
    import argparse

    parser = argparse.ArgumentParser(description="Run the Cyber KB React Agent")
    parser.add_argument(
        "--interactive", "-i", action="store_true", help="Run in interactive mode"
    )
    parser.add_argument("--test", "-t", action="store_true", help="Run test queries")
    args = parser.parse_args()

    # Run in the appropriate mode
    if args.interactive:
        interactive_mode(agent)
    elif args.test:
        run_test_queries(agent)
    else:
        # Default: run interactive mode
        interactive_mode(agent)


if __name__ == "__main__":
    main()
