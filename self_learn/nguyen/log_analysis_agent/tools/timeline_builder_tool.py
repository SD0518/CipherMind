from langchain_core.tools import tool
from typing import Dict, Any, List
from datetime import datetime
import re
import json
from .base_tool import Tool

class TimelineBuilderTool(Tool):
    """Build focused timelines around suspicious events by parsing raw logs directly"""
    
    def name(self) -> str:
        return "timeline_builder"

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            pivot_entity = input_data.get("pivot_entity", "")
            pivot_type = input_data.get("pivot_type", "")
            time_window_minutes = int(input_data.get("time_window_minutes", 5))
            raw_logs = input_data.get("raw_logs", "")
            
            if not pivot_entity or not pivot_type:
                return {"error": "Both pivot_entity and pivot_type are required"}
            
            if not raw_logs:
                return {"error": "No raw log data provided"}
            
            # Parse events from raw logs
            events = self._parse_raw_logs(raw_logs)
            
            if not events:
                return {
                    "tool": "timeline_builder",
                    "pivot_entity": pivot_entity,
                    "pivot_type": pivot_type,
                    "result": {
                        "found": False,
                        "message": "No events could be parsed from logs",
                        "timeline": []
                    }
                }
            
            # Find pivot events
            pivot_events = self._find_pivot_events(events, pivot_entity, pivot_type)
            
            if not pivot_events:
                return {
                    "tool": "timeline_builder",
                    "pivot_entity": pivot_entity,
                    "pivot_type": pivot_type,
                    "result": {
                        "found": False,
                        "message": f"No events found for {pivot_type}: {pivot_entity}",
                        "total_events_parsed": len(events),
                        "timeline": []
                    }
                }
            
            # Build timeline around first pivot event (limit scope)
            pivot_event = pivot_events[0]
            timeline = self._build_timeline_around_event(
                events, pivot_event, time_window_minutes
            )
            
            # Generate summary
            summary = self._generate_timeline_summary(
                pivot_event, timeline, len(pivot_events)
            )
            
            return {
                "tool": "timeline_builder",
                "pivot_entity": pivot_entity,
                "pivot_type": pivot_type,
                "time_window_minutes": time_window_minutes,
                "result": {
                    "found": True,
                    "total_pivot_events": len(pivot_events),
                    "showing_timeline_for": "first pivot event",
                    "pivot_event_summary": self._summarize_event(pivot_event),
                    "timeline": timeline,
                    "summary": summary
                }
            }
            
        except Exception as e:
            return {"error": f"{type(e).__name__}: {str(e)}"}
    
    def _parse_raw_logs(self, raw_logs: str) -> List[Dict]:
        """Parse events from raw log string"""
        events = []
        
        # Try to parse as JSON lines
        for line in raw_logs.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            try:
                # Try parsing as JSON
                event = json.loads(line)
                parsed_event = self._extract_event_data(event)
                if parsed_event:
                    events.append(parsed_event)
            except json.JSONDecodeError:
                # Try parsing as plain text log
                parsed_event = self._parse_text_log_line(line)
                if parsed_event:
                    events.append(parsed_event)
        
        return events
    
    def _extract_event_data(self, event: Dict) -> Dict:
        """Extract relevant fields from a JSON event"""
        extracted = {
            "raw": event,
            "timestamp": None,
            "event_id": None,
            "user": None,
            "computer": None,
            "process_name": None,
            "command_line": None,
            "src_ip": None,
            "dst_ip": None,
            "file_path": None,
            "registry_path": None
        }
        
        # Extract timestamp (try multiple formats)
        for ts_field in ["@timestamp", "timestamp", "TimeCreated", "EventTime"]:
            if ts_field in event:
                extracted["timestamp"] = self._parse_timestamp(event[ts_field])
                break
        
        # Extract Event ID
        for id_field in ["EventID", "event_id", "event.code", "winlog.event_id"]:
            if id_field in event:
                extracted["event_id"] = str(event[id_field])
                break
        
        # Extract user
        for user_field in ["User", "user", "user.name", "winlog.user.name", "SubjectUserName"]:
            if user_field in event:
                extracted["user"] = str(event[user_field])
                break
        
        # Extract computer/host
        for comp_field in ["Computer", "computer", "host.name", "winlog.computer_name"]:
            if comp_field in event:
                extracted["computer"] = str(event[comp_field])
                break
        
        # Extract process info
        for proc_field in ["Image", "process.name", "NewProcessName", "ProcessName"]:
            if proc_field in event:
                extracted["process_name"] = str(event[proc_field])
                break
        
        for cmd_field in ["CommandLine", "command_line", "process.command_line"]:
            if cmd_field in event:
                extracted["command_line"] = str(event[cmd_field])
                break
        
        # Extract network info
        for src_field in ["SourceIp", "src_ip", "source.ip"]:
            if src_field in event:
                extracted["src_ip"] = str(event[src_field])
                break
        
        for dst_field in ["DestinationIp", "dst_ip", "destination.ip"]:
            if dst_field in event:
                extracted["dst_ip"] = str(event[dst_field])
                break
        
        # Extract file info
        for file_field in ["TargetFilename", "file.path", "ObjectName"]:
            if file_field in event:
                extracted["file_path"] = str(event[file_field])
                break
        
        # Extract registry info
        for reg_field in ["TargetObject", "registry.path"]:
            if reg_field in event:
                extracted["registry_path"] = str(event[reg_field])
                break
        
        return extracted
    
    def _parse_text_log_line(self, line: str) -> Dict:
        """Parse a plain text log line"""
        extracted = {
            "raw": {"text": line},
            "timestamp": None,
            "event_id": None,
            "user": None,
            "computer": None,
            "process_name": None,
            "command_line": None,
            "src_ip": None,
            "dst_ip": None,
            "file_path": None,
            "registry_path": None
        }
        
        # Try to extract timestamp
        ts_match = re.search(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}', line)
        if ts_match:
            extracted["timestamp"] = self._parse_timestamp(ts_match.group(0))
        
        # Try to extract Event ID
        event_id_match = re.search(r'EventID[:\s=]+(\d+)', line, re.IGNORECASE)
        if event_id_match:
            extracted["event_id"] = event_id_match.group(1)
        
        # Try to extract IP addresses
        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        if ip_matches:
            extracted["src_ip"] = ip_matches[0]
            if len(ip_matches) > 1:
                extracted["dst_ip"] = ip_matches[1]
        
        return extracted
    
    def _parse_timestamp(self, ts_value) -> datetime:
        """Parse timestamp from various formats"""
        if isinstance(ts_value, datetime):
            return ts_value
        
        if isinstance(ts_value, (int, float)):
            return datetime.fromtimestamp(ts_value)
        
        ts_str = str(ts_value)
        
        # Try common formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        
        return None
    
    def _find_pivot_events(self, events: List[Dict], pivot_entity: str, pivot_type: str) -> List[Dict]:
        """Find events that match the pivot criteria"""
        pivot_events = []
        pivot_entity_lower = pivot_entity.lower()
        
        for event in events:
            if self._event_matches_pivot(event, pivot_entity_lower, pivot_type.lower()):
                pivot_events.append(event)
        
        return pivot_events
    
    def _event_matches_pivot(self, event: Dict, pivot_entity: str, pivot_type: str) -> bool:
        """Check if an event matches the pivot criteria"""
        if pivot_type == "user":
            user = (event.get('user') or '').lower()
            return pivot_entity in user
        
        elif pivot_type == "process":
            process_name = (event.get('process_name') or '').lower()
            command_line = (event.get('command_line') or '').lower()
            return pivot_entity in process_name or pivot_entity in command_line
        
        elif pivot_type == "ip":
            src_ip = (event.get('src_ip') or '').lower()
            dst_ip = (event.get('dst_ip') or '').lower()
            return pivot_entity in src_ip or pivot_entity in dst_ip
        
        elif pivot_type == "file":
            file_path = (event.get('file_path') or '').lower()
            return pivot_entity in file_path
        
        elif pivot_type == "computer":
            computer = (event.get('computer') or '').lower()
            return pivot_entity in computer
        
        elif pivot_type == "event_id":
            event_id = str(event.get('event_id') or '').lower()
            return pivot_entity in event_id
        
        elif pivot_type == "registry":
            registry_path = (event.get('registry_path') or '').lower()
            return pivot_entity in registry_path
        
        return False
    
    def _build_timeline_around_event(self, events: List[Dict], pivot_event: Dict, time_window_minutes: int) -> List[Dict]:
        """Build a timeline of events around a pivot event"""
        pivot_timestamp = pivot_event.get('timestamp')
        
        # If no timestamp, just show events around the pivot in sequence
        if not pivot_timestamp:
            pivot_idx = events.index(pivot_event)
            start_idx = max(0, pivot_idx - 10)
            end_idx = min(len(events), pivot_idx + 11)
            
            timeline = []
            for i, event in enumerate(events[start_idx:end_idx]):
                timeline.append({
                    "sequence_position": i,
                    "is_pivot": event == pivot_event,
                    "event_summary": self._summarize_event(event)
                })
            return timeline
        
        # Build timeline based on timestamps
        from datetime import timedelta
        start_time = pivot_timestamp - timedelta(minutes=time_window_minutes)
        end_time = pivot_timestamp + timedelta(minutes=time_window_minutes)
        
        timeline = []
        for event in events:
            event_timestamp = event.get('timestamp')
            if event_timestamp and start_time <= event_timestamp <= end_time:
                offset_seconds = (event_timestamp - pivot_timestamp).total_seconds()
                timeline.append({
                    "timestamp": event_timestamp.isoformat(),
                    "offset_seconds": offset_seconds,
                    "offset_human": self._format_time_offset(offset_seconds),
                    "is_pivot": event == pivot_event,
                    "event_summary": self._summarize_event(event)
                })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x.get('timestamp', ''))
        
        return timeline
    
    def _format_time_offset(self, offset_seconds: float) -> str:
        """Format time offset in human readable form"""
        if offset_seconds == 0:
            return "PIVOT EVENT"
        elif offset_seconds < 0:
            return f"{abs(offset_seconds):.1f}s before"
        else:
            return f"{offset_seconds:.1f}s after"
    
    def _summarize_event(self, event: Dict) -> str:
        """Create a human-readable summary of an event"""
        parts = []
        
        if event.get('event_id'):
            parts.append(f"EventID {event['event_id']}")
        
        if event.get('user'):
            parts.append(f"User: {event['user']}")
        
        if event.get('process_name'):
            parts.append(f"Process: {event['process_name']}")
        
        if event.get('command_line'):
            cmd = event['command_line']
            if len(cmd) > 60:
                cmd = cmd[:57] + "..."
            parts.append(f"CMD: {cmd}")
        
        if event.get('src_ip') or event.get('dst_ip'):
            if event.get('src_ip') and event.get('dst_ip'):
                parts.append(f"Network: {event['src_ip']} → {event['dst_ip']}")
            elif event.get('src_ip'):
                parts.append(f"SrcIP: {event['src_ip']}")
            elif event.get('dst_ip'):
                parts.append(f"DstIP: {event['dst_ip']}")
        
        if event.get('file_path'):
            parts.append(f"File: {event['file_path']}")
        
        if event.get('registry_path'):
            parts.append(f"Registry: {event['registry_path']}")
        
        return " | ".join(parts) if parts else "No details available"
    
    def _generate_timeline_summary(self, pivot_event: Dict, timeline: List[Dict], total_pivot_count: int) -> str:
        """Generate a human-readable summary of the timeline"""
        summary_parts = []
        
        summary_parts.append(f"Found {total_pivot_count} matching event(s).")
        summary_parts.append(f"Timeline shows {len(timeline)} events around the first match.")
        
        # Count events before/after pivot
        before = sum(1 for e in timeline if e.get('offset_seconds', 1) < 0)
        after = sum(1 for e in timeline if e.get('offset_seconds', 1) > 0)
        
        if before or after:
            summary_parts.append(f"{before} events before, {after} events after pivot.")
        
        # Identify interesting patterns
        event_ids = [e['event_summary'] for e in timeline if 'EventID' in e.get('event_summary', '')]
        if len(set(event_ids)) < len(event_ids):
            summary_parts.append("Multiple similar events detected in sequence.")
        
        return " ".join(summary_parts)


# Create singleton instance
_timeline_builder_tool = TimelineBuilderTool()

@tool
def timeline_builder(pivot_entity: str, pivot_type: str, time_window_minutes: int = 5, raw_logs: str = None) -> dict:
    """Build a focused timeline around suspicious events to understand attack sequences.
    
    Use this when you suspect coordinated activity or want to understand what happened 
    before and after a suspicious event. Analyzes the sequence of events to identify patterns.
    
    Args:
        pivot_entity: The entity to build timeline around (e.g., "powershell.exe", "admin", "192.168.1.100")
        pivot_type: Type of entity - "user", "process", "ip", "file", "computer", "event_id", or "registry"
        time_window_minutes: Minutes before and after pivot events to include (default: 5)
        raw_logs: The raw log data (automatically provided by agent)
    
    Returns:
        Timeline analysis showing events before and after the pivot, helping identify attack sequences.
    """
    return _timeline_builder_tool.run({
        "pivot_entity": pivot_entity,
        "pivot_type": pivot_type, 
        "time_window_minutes": time_window_minutes,
        "raw_logs": raw_logs
    })