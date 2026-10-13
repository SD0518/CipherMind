from typing import Any, Dict, List, Optional
from typing_extensions import TypedDict
from langgraph.graph import StateGraph, END
from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field
import json
import os
import argparse
import sys
import re
from datetime import datetime
from dotenv import load_dotenv
from tools import ShodanTool, VirusTotalTool
from prompt import LOG_AGENT_PROMPT


# ----- Pydantic Schemas -----
class AbnormalEvent(BaseModel):
    event_id: str = Field(description="Windows Event ID (e.g., 5156, 4688)")
    event_description: str = Field(description="What happened")
    why_abnormal: str = Field(description="Why suspicious")
    severity: str = Field(description="LOW|MEDIUM|HIGH|CRITICAL")
    indicators: List[str] = Field(description="Suspicious elements (IPs, hashes, etc.)")
    potential_threat: str = Field(description="Specific attack technique")
    attack_category: str = Field(description="credential access, privilege escalation, etc")
    tool_enrichment: Optional[dict] = Field(default=None, description="Optional enrichment data")


class LogAnalysisResult(BaseModel):
    overall_assessment: str = Field(description="NORMAL or ABNORMAL")
    total_events_analyzed: int = Field(description="Number of events analyzed")
    analysis_summary: str = Field(description="Brief overall summary")
    abnormal_event_ids: List[str] = Field(description="List of Windows Event IDs that are abnormal")
    abnormal_events: List[AbnormalEvent] = Field(description="List of abnormal events with details")



# ---------- 1) STATE ----------
class AgentState(TypedDict, total=False):
    logs: List[str]
    cursor: int
    enrichment: Dict[str, Any]        # { "shodan:1.2.3.4": {...}, "vt:abc..": {...} }
    findings: List[Dict[str, Any]]    # scratchpad of suspected events/evidence
    pending_actions: List[Dict[str, Any]]  # tool calls requested by LLM
    transcript: List[str]             # thoughts + observations
    budget: Dict[str, int]            # {"max_tool_calls": 20, "used": 0}
    done: bool

# ---------- 2) WRAP TOOLS AS LANGCHAIN TOOLS ----------
# Use your existing tool classes under the hood.
shodan = ShodanTool()
virustotal = VirusTotalTool()

class IPArgs(BaseModel):
    ip: str = Field(..., description="IP address to enrich")

class HashArgs(BaseModel):
    hash: str = Field(..., description="File hash to check reputation")

@tool("shodan_lookup", args_schema=IPArgs)
def shodan_lookup(ip: str) -> Dict[str, Any]:
    """Infra lookup for an IP (open ports, banners, tags)."""
    try:
        return shodan.run({"ioc": ip})
    except Exception as e:
        return {"error": str(e)}

@tool("virustotal_lookup_ip", args_schema=IPArgs)
def virustotal_lookup_ip(ip: str) -> Dict[str, Any]:
    """Reputation lookup for IP on VirusTotal."""
    try:
        return virustotal.run({"ioc": ip})
    except Exception as e:
        return {"error": str(e)}

@tool("virustotal_lookup_hash", args_schema=HashArgs)
def virustotal_lookup_hash(hash: str) -> Dict[str, Any]:
    """Reputation lookup for a file hash on VirusTotal."""
    try:
        return virustotal.run({"ioc": hash})
    except Exception as e:
        return {"error": str(e)}

TOOLS = [shodan_lookup, virustotal_lookup_ip, virustotal_lookup_hash]

# ---------- 3) LLM WITH TOOLS BOUND ----------
env_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path=env_path)
api_key = os.getenv('GEMINI_API_KEY')
if not api_key:
    raise ValueError("GEMINI_API_KEY not found. Please set it in .env file or environment variable.")

llm = ChatGoogleGenerativeAI(
    model="gemini-1.5-flash",
    google_api_key=api_key,
    temperature=0.1,
    max_output_tokens=3000
).bind_tools(TOOLS)

# Small helper prompt that drives a ReAct-style step. The LLM can either:
# - produce analysis (no tool call), or
# - produce a tool call (function-calling) for one IOC at a time.
STEP_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a SOC log analyst. You work one log line at a time.
You may call tools when helpful. After each tool observation, update your assessment.
Prefer precision, low hallucination. Only call a tool if it materially reduces uncertainty.
If high-confidence malicious behavior is established, say so explicitly."""),
    ("human", """LOG LINE:
{log_line}

KNOWN ENRICHMENT (prior observations):
{enrichment_context}

INSTRUCTIONS:
- If you need a tool, call exactly one tool now (function/tool call).
- Otherwise, write a short analysis statement about this line and whether it contributes to 'ABNORMAL'.
- If you used a tool previously on this line, integrate its observation now.
""")
])

# ---------- 4) REASON NODE ----------
def reason(state: AgentState) -> AgentState:
    if state.get("cursor", 0) >= len(state["logs"]):
        state["done"] = True
        return state

    line = state["logs"][state["cursor"]]
    # give the LLM only enrichment already known for IOCs it might notice later
    enrichment_context = summarize_enrichment_for_line(line, state.get("enrichment", {}))

    msg = STEP_PROMPT.format_messages(
        log_line=line,
        enrichment_context=enrichment_context or "None"
    )

    resp = llm.invoke(msg)
    state.setdefault("transcript", []).append(resp.content or "")

    # If the model requested a tool (function calling), we'll capture it:
    tool_calls = getattr(resp, "tool_calls", None) or []
    if tool_calls:
        # process ONE tool call per step to keep loops tight
        state["pending_actions"] = [tool_calls[0]]
        return state

    # No tool: treat this as analysis for this line, move the cursor.
    # Optionally extract structured flags (quick regex/heuristic) into findings.
    maybe_capture_finding(line, resp.content, state)
    state["cursor"] += 1
    return state

# ---------- 5) ACT NODE ----------
def act(state: AgentState) -> AgentState:
    if not state.get("pending_actions"):
        return state
    if state["budget"]["used"] >= state["budget"]["max_tool_calls"]:
        # budget exhausted; skip and continue
        state["transcript"].append("[Budget] Tool call skipped (budget exhausted).")
        state["pending_actions"] = []
        state["cursor"] += 1
        return state

    call = state["pending_actions"].pop(0)
    name = call["name"]
    args = call.get("args", {}) or {}

    # dispatch
    if name == "shodan_lookup":
        obs = shodan_lookup.invoke(args)
        key = f"shodan:{args.get('ip')}"
    elif name == "virustotal_lookup_ip":
        obs = virustotal_lookup_ip.invoke(args)
        key = f"vt_ip:{args.get('ip')}"
    elif name == "virustotal_lookup_hash":
        obs = virustotal_lookup_hash.invoke(args)
        key = f"vt_hash:{args.get('hash')}"
    else:
        obs = {"error": f"Unknown tool: {name}"}
        key = f"unknown:{name}"

    # cache & record observation
    state.setdefault("enrichment", {})[key] = obs
    state["budget"]["used"] += 1
    state.setdefault("transcript", []).append(f"[Observation] {name} -> {str(obs)[:300]}")

    # Clear pending actions and advance cursor after tool execution
    state["pending_actions"] = []
    state["cursor"] += 1
    return state

# ---------- 6) ROUTER ----------
def route(state: AgentState):
    if state.get("done"):
        return "summarize"
    if state.get("pending_actions"):
        return "act"
    # If the line requested no tool (or after a tool, we go reason again)
    if state.get("cursor", 0) < len(state["logs"]):
        return "reason"
    return "summarize"

# ---------- 7) SUMMARIZE ----------
final_parser = JsonOutputParser(pydantic_object=LogAnalysisResult)

def summarize(state: AgentState) -> AgentState:
    # Build a compact “evidence package” for the final report
    final_prompt = f"""{LOG_AGENT_PROMPT}

You will produce a final, structured incident assessment from the transcript and enrichment.

TRANSCRIPT (reasoning steps & tool observations, most recent last):
{format_transcript(state.get("transcript", []))}

ENRICHMENT (deduplicated):
{safe_json(state.get("enrichment", {}))}

Return a JSON matching this schema:
{final_parser.get_format_instructions()}
"""
    # You can use the same LLM (no tools needed here)
    resp = ChatGoogleGenerativeAI(
        model="gemini-1.5-flash", 
        google_api_key=api_key,
        temperature=0
    ).invoke(final_prompt)
    content = (resp.content or "").strip()
    try:
        result = final_parser.parse(content)
        state["final"] = result
    except Exception as e:
        print(f"Error parsing final result: {e}")
        print(f"Raw content: {content[:500]}...")
        # Create a fallback result
        state["final"] = LogAnalysisResult(
            overall_assessment="ABNORMAL",
            total_events_analyzed=len(state.get("logs", [])),
            analysis_summary="Analysis completed with parsing errors",
            abnormal_event_ids=[],
            abnormal_events=[]
        )
    return state

# ---------- helpers ----------
def summarize_enrichment_for_line(line: str, enrichment: Dict[str, Any]) -> str:
    # optional: pull IPs/hashes from line and show any cached enrichment for them
    # keep tiny to avoid prompt bloat
    return safe_json({k: v for k, v in enrichment.items() if any(tok in k for tok in line.split())})

def maybe_capture_finding(line: str, analysis: str, state: AgentState) -> None:
    # optional: heuristic capture into state["findings"]
    if "suspicious" in (analysis or "").lower():
        state.setdefault("findings", []).append({"line": line, "note": analysis})

def format_transcript(steps: List[str]) -> str:
    return "\n".join(f"- {s}" for s in steps[-50:])  # keep tail

def safe_json(obj: Any) -> str:
    import json
    try:
        return json.dumps(obj, indent=2)[:4000]
    except Exception:
        return str(obj)[:4000]

# ---------- build graph ----------
workflow = StateGraph(AgentState)
workflow.add_node("reason", reason)
workflow.add_node("act", act)
workflow.add_node("summarize", summarize)

workflow.set_entry_point("reason")
workflow.add_conditional_edges("reason", route, {"reason": "reason", "act": "act", "summarize": "summarize"})
workflow.add_conditional_edges("act", route, {"reason": "reason", "act": "act", "summarize": "summarize"})
workflow.add_edge("summarize", END)
app = workflow.compile()

# ---------- run ----------
def run_agentic(log_text: str) -> LogAnalysisResult:
    lines = log_text.splitlines()
    # Limit to first 100 lines to avoid recursion issues with large files
    if len(lines) > 100:
        print(f"Large file detected ({len(lines)} lines). Processing first 100 lines only.")
        lines = lines[:100]
    
    initial: AgentState = {
        "logs": lines,
        "cursor": 0,
        "enrichment": {},
        "findings": [],
        "pending_actions": [],
        "transcript": [],
        "budget": {"max_tool_calls": 20, "used": 0},
        "done": False,
    }
    # Use config to increase recursion limit
    config = {"recursion_limit": 1000}
    try:
        out = app.invoke(initial, config=config)
        print(f"Workflow completed. Output keys: {list(out.keys())}")
        if "final" in out:
            return out["final"]
        else:
            print("No 'final' key found in output. Creating fallback result.")
            return LogAnalysisResult(
                overall_assessment="ABNORMAL",
                total_events_analyzed=len(initial["logs"]),
                analysis_summary="Analysis completed but final result not properly set",
                abnormal_event_ids=[],
                abnormal_events=[]
            )
    except Exception as e:
        print(f"Workflow execution error: {e}")
        return LogAnalysisResult(
            overall_assessment="ERROR",
            total_events_analyzed=len(initial["logs"]),
            analysis_summary=f"Analysis failed: {str(e)}",
            abnormal_event_ids=[],
            abnormal_events=[]
        )


def main():
    parser = argparse.ArgumentParser(description='Simple Tools Cybersecurity Log Analysis Agent')
    parser.add_argument('log_file', help='Path to log file (any format: JSON, JSONL, CSV, txt)')
    parser.add_argument('-o', '--output', help='Output file path (optional)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        # Load log file content
        with open(args.log_file, 'r', encoding='utf-8') as f:
            log_content = f.read()
        
        print(f"Loaded log file: {args.log_file}")
        print(f"File size: {len(log_content)} characters")
        
        # Run analysis
        result = run_agentic(log_content)
        
        print(f"\nTools Agent execution completed!")
        print("Result:", result)
        
    except ValueError as e:
        print(f"Setup Error: {e}")
        print("Get your free Gemini API key at: https://aistudio.google.com/app/apikey")
        sys.exit(1)
    except Exception as e:
        print(f"Execution Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
