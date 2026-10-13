from langchain_core.tools import tool
from typing import Dict, Any, List
from .base_tool import Tool

class FieldReducerTool(Tool):
    """Keep existing implementation"""
    def name(self) -> str:
        return "fieldreducer"

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            candidates: List[str] = input_data.get("candidates", []) or []
            max_fields: int = int(input_data.get("max_fields", 3) or 3)
            method: str = input_data.get("priority", "impact") or "impact"

            if not isinstance(candidates, list):
                return {"error": "candidates must be a list of field names"}

            priority_order = [
                "event_id", "command_line", "dst_ip", "src_ip", "hash",
                "registry_path", "user", "image", "parent_image",
                "dst_port", "src_port", "protocol",
            ]

            def score_key(field_name: str) -> int:
                try:
                    return priority_order.index(field_name)
                except ValueError:
                    return len(priority_order)

            sorted_candidates = sorted(candidates, key=score_key)
            selected = sorted_candidates[:max_fields]

            return {
                "tool": "fieldreducer",
                "selected_names": selected,
                "total_candidates": len(candidates),
                "method": method,
                "max_fields": max_fields
            }

        except Exception as e:
            return {"error": f"{type(e).__name__}: {str(e)}"}

# Create singleton instance
_fieldreducer_tool = FieldReducerTool()

@tool
def fieldreducer(field_names: List[str], max_fields: int = 10) -> dict:
    """Identifies the most security-critical fields from complex log data to focus analysis.
    
    Use this tool when logs contain many fields (10+) and you need to prioritize which data points
    are most likely to reveal security threats. This helps avoid analysis paralysis with verbose logs.
    
    Args:
        field_names: List of field names from the log data (e.g., ["dst_ip", "src_ip", "event_id", "user"])
        max_fields: Maximum number of priority fields to return (default: 10)
    
    Returns:
        Prioritized list of fields most relevant for cybersecurity analysis.
    """
    return _fieldreducer_tool.run({"candidates": field_names, "max_fields": max_fields})