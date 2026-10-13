#!/usr/bin/env python3
"""
Log Analyzer for Windows Security Events
Analyzes JSON security log files to identify different log types and their field patterns.
"""

import json
import sys
from collections import defaultdict, Counter
from typing import Dict, List, Set, Any
import argparse

class LogAnalyzer:
    def __init__(self):
        self.event_types = defaultdict(list)
        self.field_patterns = defaultdict(set)
        self.event_count = defaultdict(int)
        self.source_names = defaultdict(int)
        self.event_id_mapping = {}
        self.line_ranges = defaultdict(list)
        
    def analyze_log_file(self, file_path: str) -> None:
        """Analyze the log file and categorize different log types."""
        print(f"Analyzing log file: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file, 1):
                try:
                    log_entry = json.loads(line.strip())
                    self._categorize_event(log_entry, line_num)
                except json.JSONDecodeError:
                    print(f"Warning: Invalid JSON at line {line_num}")
                    continue
                except Exception as e:
                    print(f"Warning: Error processing line {line_num}: {e}")
                    continue
    
    def _categorize_event(self, event: Dict[str, Any], line_num: int) -> None:
        """Categorize a single event based on its properties."""
        # Extract key identifiers
        event_id = event.get('EventID', 'Unknown')
        source_name = event.get('SourceName', 'Unknown')
        channel = event.get('Channel', 'Unknown')
        category = event.get('Category', event.get('Task', 'Unknown'))
        
        # Create a unique event type identifier
        event_type_key = f"{source_name}::{event_id}"
        
        # Store event information
        self.event_types[event_type_key].append({
            'line_num': line_num,
            'event': event,
            'channel': channel,
            'category': category
        })
        
        # Count events
        self.event_count[event_type_key] += 1
        self.source_names[source_name] += 1
        
        # Track line ranges for each event type
        self.line_ranges[event_type_key].append(line_num)
        
        # Extract and store field patterns
        fields = set(event.keys())
        self.field_patterns[event_type_key].update(fields)
        
        # Map event ID to description
        if event_id not in self.event_id_mapping:
            self.event_id_mapping[event_id] = {
                'description': self._get_event_description(event),
                'source': source_name,
                'channel': channel
            }
    
    def _get_event_description(self, event: Dict[str, Any]) -> str:
        """Extract event description from the event."""
        # Try different fields that might contain description
        for field in ['Message', 'Description', 'Category', 'Task']:
            if field in event and event[field]:
                desc = str(event[field])
                if len(desc) > 100:
                    # Take first line or first 100 chars of long messages
                    desc = desc.split('\r\n')[0][:100] + "..."
                return desc
        return "No description available"
    
    def print_summary(self) -> None:
        """Print a comprehensive summary of the log analysis."""
        print("\n" + "="*80)
        print("LOG ANALYSIS SUMMARY")
        print("="*80)
        
        print(f"\nTotal Event Types Found: {len(self.event_types)}")
        print(f"Total Events Processed: {sum(self.event_count.values())}")
        
        print("\n" + "-"*60)
        print("EVENT SOURCES DISTRIBUTION")
        print("-"*60)
        for source, count in sorted(self.source_names.items(), key=lambda x: x[1], reverse=True):
            print(f"{source:<50}: {count:>8} events")
        
        print("\n" + "-"*60)
        print("EVENT TYPES BY FREQUENCY")
        print("-"*60)
        
        for event_type, count in sorted(self.event_count.items(), key=lambda x: x[1], reverse=True):
            source, event_id = event_type.split('::', 1)
            line_ranges = self.line_ranges[event_type]
            min_line = min(line_ranges)
            max_line = max(line_ranges)
            
            print(f"\nEvent Type: {event_type}")
            print(f"  Count: {count}")
            print(f"  Lines: {min_line}-{max_line}")
            print(f"  Description: {self.event_id_mapping.get(event_id, {}).get('description', 'N/A')}")
            
            # Show first occurrence details
            first_event = self.event_types[event_type][0]['event']
            print(f"  Channel: {first_event.get('Channel', 'N/A')}")
            print(f"  Category: {first_event.get('Category', first_event.get('Task', 'N/A'))}")
    
    def print_detailed_field_analysis(self) -> None:
        """Print detailed field analysis for each event type."""
        print("\n" + "="*80)
        print("DETAILED FIELD ANALYSIS")
        print("="*80)
        
        for event_type in sorted(self.event_types.keys()):
            fields = sorted(self.field_patterns[event_type])
            count = self.event_count[event_type]
            
            print(f"\n{'-'*60}")
            print(f"Event Type: {event_type} ({count} occurrences)")
            print(f"{'-'*60}")
            
            # Show sample line numbers
            sample_lines = self.line_ranges[event_type][:5]
            if len(sample_lines) > 5:
                print(f"Sample Lines: {', '.join(map(str, sample_lines))}... (and {len(self.line_ranges[event_type]) - 5} more)")
            else:
                print(f"Lines: {', '.join(map(str, sample_lines))}")
            
            print(f"Total Fields: {len(fields)}")
            print("Fields:")
            
            # Group fields by type for better readability
            core_fields = []
            time_fields = []
            process_fields = []
            network_fields = []
            security_fields = []
            other_fields = []
            
            for field in fields:
                field_lower = field.lower()
                if field in ['EventID', 'SourceName', 'Channel', 'Message', 'Category', 'Task']:
                    core_fields.append(field)
                elif 'time' in field_lower or 'date' in field_lower:
                    time_fields.append(field)
                elif any(x in field_lower for x in ['process', 'image', 'command', 'parent', 'pid']):
                    process_fields.append(field)
                elif any(x in field_lower for x in ['address', 'port', 'network', 'protocol', 'connection']):
                    network_fields.append(field)
                elif any(x in field_lower for x in ['user', 'logon', 'security', 'access', 'permission', 'hash']):
                    security_fields.append(field)
                else:
                    other_fields.append(field)
            
            if core_fields:
                print(f"  Core Fields ({len(core_fields)}): {', '.join(core_fields)}")
            if time_fields:
                print(f"  Time Fields ({len(time_fields)}): {', '.join(time_fields)}")
            if process_fields:
                print(f"  Process Fields ({len(process_fields)}): {', '.join(process_fields)}")
            if network_fields:
                print(f"  Network Fields ({len(network_fields)}): {', '.join(network_fields)}")
            if security_fields:
                print(f"  Security Fields ({len(security_fields)}): {', '.join(security_fields)}")
            if other_fields:
                print(f"  Other Fields ({len(other_fields)}): {', '.join(other_fields)}")
    
    def print_event_transitions(self) -> None:
        """Show where different event types appear in the log file."""
        print("\n" + "="*80)
        print("EVENT TYPE TRANSITIONS (Sample)")
        print("="*80)
        
        # Create a timeline of events
        timeline = []
        for event_type, events in self.event_types.items():
            for event_info in events:
                timeline.append((event_info['line_num'], event_type))
        
        # Sort by line number
        timeline.sort(key=lambda x: x[0])
        
        # Show transitions (where event type changes)
        prev_event_type = None
        transition_count = 0
        
        print("Line Range Transitions:")
        for line_num, event_type in timeline:
            if prev_event_type and prev_event_type != event_type:
                transition_count += 1
                if transition_count <= 20:  # Show first 20 transitions
                    print(f"  Line {line_num}: {prev_event_type} → {event_type}")
                elif transition_count == 21:
                    print("  ... (showing first 20 transitions)")
            prev_event_type = event_type
        
        print(f"\nTotal Event Type Transitions: {transition_count}")
    
    def export_analysis_to_file(self, output_path: str) -> None:
        """Export the analysis results to a file."""
        with open(output_path, 'w', encoding='utf-8') as f:
            # Redirect print to file
            original_stdout = sys.stdout
            sys.stdout = f
            
            self.print_summary()
            self.print_detailed_field_analysis()
            self.print_event_transitions()
            
            # Restore stdout
            sys.stdout = original_stdout
        
        print(f"Analysis exported to: {output_path}")

def main():
    parser = argparse.ArgumentParser(description='Analyze Windows Security Event Logs')
    parser.add_argument('log_file', help='Path to the JSON log file')
    parser.add_argument('--output', '-o', help='Output file for analysis results')
    parser.add_argument('--detailed', '-d', action='store_true', 
                       help='Show detailed field analysis')
    
    args = parser.parse_args()
    
    # Create analyzer and process file
    analyzer = LogAnalyzer()
    
    try:
        analyzer.analyze_log_file(args.log_file)
        
        # Print results
        analyzer.print_summary()
        
        if args.detailed:
            analyzer.print_detailed_field_analysis()
            analyzer.print_event_transitions()
        
        # Export to file if requested
        if args.output:
            analyzer.export_analysis_to_file(args.output)
            
    except FileNotFoundError:
        print(f"Error: File '{args.log_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
