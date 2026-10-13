from langchain_core.tools import tool
from typing import Dict, Any
import re
from .base_tool import Tool

class EventIDExtractorTool(Tool):
    """Keep existing implementation"""
    def name(self) -> str:
        return "event_id_extractor"

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            suspected_id = input_data.get("suspected_event_id", "")
            raw_logs = input_data.get("raw_logs", "")
            
            if not suspected_id:
                return {"error": "No suspected event ID provided"}
            if not raw_logs:
                return {"error": "No raw logs provided"}

            for line in raw_logs.split('\n'):
                if suspected_id in line:
                    eventid_patterns = [
                        r'"EventID"\s*:\s*"?(\d+)"?',
                        r'EventID[:\s=]+"?(\d+)"?',
                        r'Event\s*ID[:\s=]+"?(\d+)"?',
                        r'event_id[:\s=]+"?(\d+)"?',
                        r'<EventID>(\d+)</EventID>',
                    ]
                    
                    for pattern in eventid_patterns:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match and match.group(1) == suspected_id:
                            return {
                                "tool": "event_id_extractor",
                                "extracted_event_id": suspected_id,
                                "found": True,
                                "was_correct": True,
                                "explanation": f"Suspected ID {suspected_id} is actually the correct EventID"
                            }
                    
                    for pattern in eventid_patterns:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            real_event_id = match.group(1)
                            return {
                                "tool": "event_id_extractor", 
                                "extracted_event_id": real_event_id,
                                "found": True,
                                "was_correct": False,
                                "explanation": f"Found suspected ID {suspected_id} in line but it's not EventID field, actual EventID is {real_event_id}",
                                "matched_line": line[:200] + "..." if len(line) > 200 else line
                            }
                    
                    return {
                        "tool": "event_id_extractor",
                        "extracted_event_id": "NO_EVENTID_IN_LINE", 
                        "found": False,
                        "was_correct": False,
                        "explanation": f"Found suspected ID {suspected_id} in line but no EventID field detected",
                        "matched_line": line[:200] + "..." if len(line) > 200 else line
                    }

            return {
                "tool": "event_id_extractor",
                "extracted_event_id": "NOT_FOUND",
                "found": False, 
                "was_correct": False,
                "explanation": f"Suspected ID {suspected_id} not found in any log line"
            }

        except Exception as e:
            return {"error": f"{type(e).__name__}: {str(e)}"}

# Create singleton instance
_event_id_extractor_tool = EventIDExtractorTool()

@tool
def event_id_extractor(suspected_event_id: str, raw_logs: str) -> dict:
    """Validates and corrects Windows Event IDs identified in log analysis.
    
    Use this tool for ANY event ID you plan to include in your final analysis to ensure accuracy.
    This tool searches the raw logs to confirm if a suspected ID is actually the EventID field
    or if it belongs to another field (like RecordNumber).
    
    Args:
        suspected_event_id: The event ID number you think is correct (e.g., "4656", "4663")
        raw_logs: The complete raw log data to search for validation
    
    Returns:
        Confirmation if the ID is correct, or the actual EventID if it was wrong.
    """
    return _event_id_extractor_tool.run({
        "suspected_event_id": suspected_event_id,
        "raw_logs": raw_logs
    })