import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI

# Import the @tool decorated functions (not the classes)
from tools.shodan_tool import shodan_lookup
from tools.virustotal_tool import virustotal_lookup, virustotal_metadata_search
from tools.fieldreducer_tool import fieldreducer
from tools.event_id_extractor_tool import event_id_extractor
from tools.timeline_builder_tool import timeline_builder
from tools.decoder_tool import decoder

# ----- LLM Setup -----
def get_llm():
    """Initialize and return the LLM instance (without tools)"""
    load_dotenv()
    return ChatGoogleGenerativeAI(
        model="gemini-2.0-flash",
        google_api_key=os.getenv("GEMINI_API_KEY"),
        temperature=0.1,
        max_output_tokens=3000,
    )

# ----- Tool Setup -----
def get_tools():
    """Return list of available tools for the agent"""
    return [
        shodan_lookup,
        virustotal_lookup,
        virustotal_metadata_search,
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
        "formatted_time": f"{minutes}m {seconds:.2f}s" if minutes > 0 else f"{seconds:.2f}s"
    }