"""
MITRE ATT&CK Cyber Knowledge Base Management Script

This script manages the MITRE ATT&CK techniques knowledge base with:
- Processing techniques.json file containing MITRE ATT&CK data
- Semantic search using google/embeddinggemma-300m embeddings
- Cross-encoder reranking using Qwen/Qwen3-Reranker-0.6B
- Hybrid search combining ChromaDB (semantic) and BM25 (keyword)
- Metadata filtering by tactics, platforms, and technique attributes

Usage:
    python build_cyber_database.py ingest --techniques-json ./mitre_data/techniques.json
    python build_cyber_database.py test --query "process injection"
    python build_cyber_database.py test --interactive
    python build_cyber_database.py test --query "privilege escalation" --filter-tactics "privilege-escalation" --filter-platforms "Windows"
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Optional, List

# Add the project root to Python path so we can import from src
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from langchain.text_splitter import TokenTextSplitter
from src.knowledge_base.cyber_knowledge_base import CyberKnowledgeBase


def truncate_to_tokens(text: str, max_tokens: int = 300) -> str:
    """
    Truncate text to a maximum number of tokens using LangChain's TokenTextSplitter.

    Args:
        text: The text to truncate
        max_tokens: Maximum number of tokens (default: 300)

    Returns:
        Truncated text within the token limit
    """
    if not text:
        return ""

    # Clean the text by replacing newlines with spaces
    cleaned_text = text.replace("\n", " ")

    # Use TokenTextSplitter to split by tokens
    splitter = TokenTextSplitter(
        encoding_name="cl100k_base", chunk_size=max_tokens, chunk_overlap=0
    )

    chunks = splitter.split_text(cleaned_text)
    return chunks[0] if chunks else ""


def validate_techniques_file(techniques_json_path: str) -> bool:
    """Validate that techniques.json exists and is readable"""

    if not os.path.exists(techniques_json_path):
        print(f"[ERROR] Techniques file not found: {techniques_json_path}")
        return False

    try:
        import json

        with open(techniques_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            print(f"[ERROR] Invalid format: techniques.json should contain a list")
            return False

        if len(data) == 0:
            print(f"[ERROR] Empty techniques file")
            return False

        # Check first item has required fields
        first_technique = data[0]
        required_fields = ["attack_id", "name", "description"]
        missing_fields = [
            field for field in required_fields if field not in first_technique
        ]

        if missing_fields:
            print(f"[ERROR] Missing required fields in techniques: {missing_fields}")
            return False

        print(f"[SUCCESS] Valid techniques file with {len(data)} techniques")
        return True

    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON format: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Error reading techniques file: {e}")
        return False


def ingest_techniques(args):
    """Ingest MITRE ATT&CK techniques and build knowledge base"""

    print("=" * 60)
    print("[INFO] INGESTING MITRE ATT&CK TECHNIQUES")
    print("=" * 60)

    # Validate techniques file
    if not validate_techniques_file(args.techniques_json):
        sys.exit(1)

    # Initialize knowledge base
    kb = CyberKnowledgeBase(embedding_model=args.embedding_model)

    try:
        # Build knowledge base
        kb.build_knowledge_base(
            techniques_json_path=args.techniques_json,
            persist_dir=args.persist_dir,
            reset=args.reset,
        )

        # Show final statistics
        print("\n[INFO] Knowledge Base Statistics:")
        stats = kb.get_stats()
        for key, value in stats.items():
            if isinstance(value, dict):
                print(f"   {key}:")
                for subkey, subvalue in list(value.items())[:5]:  # Show first 5 items
                    print(f"     {subkey}: {subvalue}")
                if len(value) > 5:
                    print(f"     ... and {len(value) - 5} more")
            else:
                print(f"   {key}: {value}")

        print(f"\n[SUCCESS] Knowledge base saved successfully to {args.persist_dir}!")
        return True

    except Exception as e:
        print(f"[ERROR] Error during ingestion: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_retrieval(args):
    """Test retrieval on existing knowledge base"""

    print("=" * 60)
    print("[INFO] TESTING CYBER KNOWLEDGE BASE")
    print("=" * 60)

    # Load knowledge base
    kb = CyberKnowledgeBase(embedding_model=args.embedding_model)

    # Load knowledge base
    success = kb.load_knowledge_base(persist_dir=args.persist_dir)

    if not success:
        print("[ERROR] Failed to load knowledge base. Run 'ingest' first.")
        sys.exit(1)

    # Show knowledge base stats
    print("\n[INFO] Knowledge Base Statistics:")
    stats = kb.get_stats()
    for key, value in stats.items():
        if isinstance(value, dict):
            print(f"   {key}:")
            for subkey, subvalue in list(value.items())[:5]:  # Show first 5 items
                print(f"     {subkey}: {subvalue}")
            if len(value) > 5:
                print(f"     ... and {len(value) - 5} more")
        else:
            print(f"   {key}: {value}")

    if args.interactive:
        # Interactive testing mode
        run_interactive_tests(kb)
    elif args.query:
        # Single query testing
        test_single_query(kb, args.query, args.filter_tactics, args.filter_platforms)
    else:
        # Run default test suite
        run_test_suite(kb)


def test_single_query(
    kb,
    query: str,
    filter_tactics: Optional[List[str]] = None,
    filter_platforms: Optional[List[str]] = None,
):
    """Test a single query with filters"""

    print(f"\n[INFO] Testing Query: '{query}'")
    if filter_tactics:
        print(f"[INFO] Filtering by tactics: {filter_tactics}")
    if filter_platforms:
        print(f"[INFO] Filtering by platforms: {filter_platforms}")
    print("-" * 40)

    try:
        # Test search with filters
        results = kb.search(
            query,
            top_k=20,
            filter_tactics=filter_tactics,
            filter_platforms=filter_platforms,
        )
        display_detailed_results(results)

    except Exception as e:
        print(f"[ERROR] Error during search: {e}")
        import traceback

        traceback.print_exc()


def display_detailed_results(results):
    """Display search results with detailed MITRE ATT&CK information"""

    if results:
        for i, doc in enumerate(results, 1):
            attack_id = doc.metadata.get("attack_id", "Unknown")
            name = doc.metadata.get("name", "Unknown")
            tactics_str = doc.metadata.get("tactics", "")
            platforms_str = doc.metadata.get("platforms", "")
            is_subtechnique = doc.metadata.get("is_subtechnique", False)
            mitigation_count = doc.metadata.get("mitigation_count", 0)
            mitigations = doc.metadata.get("mitigations", "")

            # Get content preview from description
            content_lines = doc.page_content.split("\n")
            description_line = next(
                (line for line in content_lines if line.startswith("Description:")), ""
            )
            if description_line:
                description = description_line.replace("Description: ", "")
                content_preview = truncate_to_tokens(description, 300)
            else:
                content_preview = truncate_to_tokens(doc.page_content, 300)

            mitigation_preview = truncate_to_tokens(mitigations, 300)

            print(f"  {i}. {attack_id} - {name}")
            print(f"     Type: {'Sub-technique' if is_subtechnique else 'Technique'}")
            print(f"     Tactics: {tactics_str if tactics_str else 'None'}")
            print(f"     Platforms: {platforms_str if platforms_str else 'None'}")
            print(
                f"     Mitigations: {mitigation_preview if mitigation_preview else 'None'}"
            )
            print(f"     Mitigation Count: {mitigation_count}")
            print(f"     Description: {content_preview}")
            print()
    else:
        print("  No results found")


def run_interactive_tests(kb):
    """Run interactive testing session with filtering options"""

    print("\n[INFO] Interactive Testing Mode")
    print("Available commands:")
    print("  - Enter a query to search")
    print("  - 'stats' to view knowledge base statistics")
    print("  - 'tactics' to list available tactics")
    print("  - 'platforms' to list available platforms")
    print(
        "  - 'filter tactics:defense-evasion,privilege-escalation query' to filter by tactics"
    )
    print("  - 'filter platforms:Windows,Linux query' to filter by platforms")
    print("  - 'technique T1055' to get specific technique info")
    print("  - 'quit' to exit")
    print("-" * 50)

    while True:
        try:
            user_input = input("\n[INPUT] Enter command: ").strip()

            if user_input.lower() in ["quit", "exit", "q"]:
                break

            if not user_input:
                continue

            # Handle special commands
            if user_input.lower() == "stats":
                display_stats(kb)
                continue

            if user_input.lower() == "tactics":
                display_available_tactics(kb)
                continue

            if user_input.lower() == "platforms":
                display_available_platforms(kb)
                continue

            # Handle technique lookup
            if user_input.lower().startswith("technique "):
                technique_id = user_input.split(" ", 1)[1].strip()
                display_technique_info(kb, technique_id)
                continue

            # Handle filtered queries
            filter_tactics = None
            filter_platforms = None
            query = user_input

            if user_input.lower().startswith("filter "):
                # Parse filter command: "filter tactics:a,b platforms:x,y query text"
                parts = user_input.split(" ")
                query_start = 1

                for i, part in enumerate(parts[1:], 1):
                    if part.startswith("tactics:"):
                        filter_tactics = part.split(":", 1)[1].split(",")
                        query_start = i + 1
                    elif part.startswith("platforms:"):
                        filter_platforms = part.split(":", 1)[1].split(",")
                        query_start = i + 1
                    else:
                        break

                query = " ".join(parts[query_start:])

            if not query.strip():
                print("[ERROR] No query provided")
                continue

            # Regular search
            print(f"\n[INFO] Search: '{query}'")
            if filter_tactics:
                print(f"[INFO] Filtering by tactics: {filter_tactics}")
            if filter_platforms:
                print(f"[INFO] Filtering by platforms: {filter_platforms}")

            results = kb.search(
                query,
                top_k=20,
                filter_tactics=filter_tactics,
                filter_platforms=filter_platforms,
            )
            display_detailed_results(results)

        except KeyboardInterrupt:
            print("\n[INFO] Exiting interactive mode...")
            break
        except Exception as e:
            print(f"[ERROR] Error: {e}")


def display_stats(kb):
    """Display detailed knowledge base statistics"""
    stats = kb.get_stats()
    print("\n[INFO] Knowledge Base Statistics:")
    for key, value in stats.items():
        if isinstance(value, dict):
            print(f"  {key}:")
            for subkey, subvalue in value.items():
                print(f"    {subkey}: {subvalue}")
        else:
            print(f"  {key}: {value}")


def display_available_tactics(kb):
    """Display available tactics"""
    stats = kb.get_stats()
    tactics = stats.get("techniques_by_tactic", {})
    if tactics:
        print("\n[INFO] Available Tactics:")
        for tactic, count in sorted(tactics.items()):
            print(f"  {tactic}: {count} techniques")
    else:
        print("\n[INFO] No tactics information available")


def display_available_platforms(kb):
    """Display available platforms"""
    stats = kb.get_stats()
    platforms = stats.get("techniques_by_platform", {})
    if platforms:
        print("\n[INFO] Available Platforms:")
        for platform, count in sorted(platforms.items()):
            print(f"  {platform}: {count} techniques")
    else:
        print("\n[INFO] No platforms information available")


def display_technique_info(kb, technique_id: str):
    """Display detailed information about a specific technique"""
    technique = kb.get_technique_by_id(technique_id.upper())
    if technique:
        print(f"\n[INFO] Technique Details: {technique_id}")
        print("-" * 40)
        print(f"Name: {technique.get('name', 'Unknown')}")
        print(
            f"Type: {'Sub-technique' if technique.get('is_subtechnique') else 'Technique'}"
        )
        print(f"Tactics: {', '.join(technique.get('tactics', []))}")
        print(f"Platforms: {', '.join(technique.get('platforms', []))}")
        print(f"Mitigations: {len(technique.get('mitigations', []))}")

        description = technique.get("description", "")
        if description:
            print(
                f"Description: {description[:500]}{'...' if len(description) > 500 else ''}"
            )

        detection = technique.get("detection", "")
        if detection:
            print(
                f"Detection: {detection[:300]}{'...' if len(detection) > 300 else ''}"
            )
    else:
        print(f"\n[ERROR] Technique {technique_id} not found")


def run_test_suite(kb):
    """Run comprehensive test suite for cyber techniques"""

    test_cases = [
        # Process injection techniques
        {"query": "process injection", "description": "Process injection techniques"},
        {"query": "DLL injection", "description": "DLL injection methods"},
        # Privilege escalation
        {
            "query": "privilege escalation Windows",
            "description": "Windows privilege escalation",
        },
        {"query": "UAC bypass", "description": "UAC bypass techniques"},
        # Persistence
        {
            "query": "scheduled task persistence",
            "description": "Scheduled task persistence",
        },
        {"query": "registry persistence", "description": "Registry-based persistence"},
        # Credential access
        {
            "query": "credential dumping LSASS",
            "description": "LSASS credential dumping",
        },
        {"query": "password spraying", "description": "Password spraying attacks"},
        # Defense evasion
        {
            "query": "defense evasion DLL hijacking",
            "description": "DLL hijacking evasion",
        },
        {"query": "process hollowing", "description": "Process hollowing technique"},
        # Lateral movement
        {"query": "lateral movement SMB", "description": "SMB lateral movement"},
        {"query": "remote desktop protocol", "description": "RDP-based movement"},
    ]

    print("\n[INFO] Running Cyber Security Test Suite:")
    print("=" * 50)

    for i, test_case in enumerate(test_cases, 1):
        print(f"\n#{i} {test_case['description']}")
        print(f"Query: '{test_case['query']}'")
        print("-" * 30)

        try:
            results = kb.search(test_case["query"], top_k=3)
            display_detailed_results(results)
        except Exception as e:
            print(f"[ERROR] Error: {e}")


def main():
    """Main entry point with argument parsing"""

    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK Cyber Knowledge Base Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python build_cyber_database.py ingest --techniques-json ./mitre_data/techniques.json
  python build_cyber_database.py test --query "process injection"
  python build_cyber_database.py test --interactive
  python build_cyber_database.py test --query "privilege escalation" --filter-tactics "privilege-escalation"
        """,
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Ingest command
    ingest_parser = subparsers.add_parser(
        "ingest", help="Ingest MITRE ATT&CK techniques and build knowledge base"
    )
    ingest_parser.add_argument(
        "--techniques-json",
        default="./mitre_data/techniques.json",
        help="Path to techniques.json file",
    )
    ingest_parser.add_argument(
        "--persist-dir",
        default="./cyber_knowledge_base",
        help="Directory to store the knowledge base",
    )
    ingest_parser.add_argument(
        "--embedding-model",
        default="google/embeddinggemma-300m",
        help="Embedding model name",
    )
    ingest_parser.add_argument(
        "--reset",
        action="store_true",
        default=True,
        help="Reset knowledge base before ingestion (default: True)",
    )
    ingest_parser.add_argument(
        "--no-reset",
        dest="reset",
        action="store_false",
        help="Do not reset existing knowledge base",
    )

    # Test command
    test_parser = subparsers.add_parser(
        "test", help="Test retrieval on existing knowledge base"
    )
    test_parser.add_argument("--query", help="Single query to test")
    test_parser.add_argument(
        "--filter-tactics",
        nargs="+",
        help="Filter by tactics (e.g., --filter-tactics defense-evasion privilege-escalation)",
    )
    test_parser.add_argument(
        "--filter-platforms",
        nargs="+",
        help="Filter by platforms (e.g., --filter-platforms Windows Linux)",
    )
    test_parser.add_argument(
        "--interactive", action="store_true", help="Interactive testing mode"
    )
    test_parser.add_argument(
        "--persist-dir",
        default="./cyber_knowledge_base",
        help="Directory where knowledge base is stored",
    )
    test_parser.add_argument(
        "--embedding-model",
        default="google/embeddinggemma-300m",
        help="Embedding model name",
    )

    args = parser.parse_args()

    if args.command == "ingest":
        success = ingest_techniques(args)
        sys.exit(0 if success else 1)

    elif args.command == "test":
        test_retrieval(args)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
