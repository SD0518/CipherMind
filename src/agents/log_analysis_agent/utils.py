import os
from dotenv import load_dotenv
from langchain.chat_models import init_chat_model
from langchain_text_splitters import TokenTextSplitter

# Import the @tool decorated functions (not the classes)
from src.agents.log_analysis_agent.tools.shodan_tool import shodan_lookup
from src.agents.log_analysis_agent.tools.virustotal_tool import (
    virustotal_lookup,
    virustotal_metadata_search,
)
from src.agents.log_analysis_agent.tools.fieldreducer_tool import fieldreducer
from src.agents.log_analysis_agent.tools.event_id_extractor_tool import (
    event_id_extractor,
)
from src.agents.log_analysis_agent.tools.timeline_builder_tool import timeline_builder
from src.agents.log_analysis_agent.tools.decoder_tool import decoder


# ----- LLM Setup -----
def get_llm():
    """Initialize and return the LLM instance (without tools)"""
    load_dotenv()
    return init_chat_model(
        "google_genai:gemini-2.0-flash",
        temperature=0.1,
    )


# ----- Tool Setup -----
def get_tools():
    """Return list of available tools for the agent"""
    return [
        # shodan_lookup,
        # virustotal_lookup,
        # virustotal_metadata_search,
        fieldreducer,
        event_id_extractor,
        timeline_builder,
        decoder,
    ]


def get_llm_with_tools():
    """Initialize and return LLM with tools bound"""
    llm = get_llm()
    tools = get_tools()
    return llm.bind_tools(tools)


# ----- Helper Functions -----
def format_execution_time(total_seconds: float) -> dict:
    """Format execution time into a readable format"""
    minutes = int(total_seconds // 60)
    seconds = total_seconds % 60

    return {
        "total_seconds": round(total_seconds, 2),
        "formatted_time": (
            f"{minutes}m {seconds:.2f}s" if minutes > 0 else f"{seconds:.2f}s"
        ),
    }


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
