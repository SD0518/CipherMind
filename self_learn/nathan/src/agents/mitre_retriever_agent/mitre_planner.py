from typing import List, Dict, Any
from mitre_query_generator import MitreQueryGenerator
from mitre_retriever import MitreRetriever
from utils.types import MitreAgentInput, AnalysisType, SeverityLevel

class MitreAnalysisPlanner:
    """Handles planning and reasoning for MITRE analysis."""

    def __init__(self, query_generator: MitreQueryGenerator):
        self.query_generator = query_generator

    def create_analysis_plan(self, log_input: MitreAgentInput) -> Dict[str, Any]:
        """Create an analysis plan based on log input."""
        print("[INFO] Creating analysis plan...")

        plan = {
            "objective": f"Analyze {log_input.analysis_type.value} findings for MITRE ATT&CK mapping",
            "priority_areas": self._identify_priority_areas(log_input),
            "search_strategy": self._determine_search_strategy(log_input),
            "expected_tactics": self._determine_expected_tactics(log_input),
            "reasoning_steps": []
        }

        return plan

    def _identify_priority_areas(self, log_input: MitreAgentInput) -> List[str]:
        """Identify priority areas for analysis based on comprehensive attack indicators."""
        areas = []

        # Initial Access: Check for email delivery, external connections, suspicious domains
        if (any('email' in event for event in log_input.event_types) or
                log_input.indicators.get('domains') or
                any('email' in source for source in log_input.log_sources) or
                'email_delivery' in log_input.event_types):
            areas.append("initial_access_techniques")

        # Execution: Process creation, malicious files
        if (log_input.processes or
                'process_creation' in log_input.event_types or
                'file_execution' in log_input.event_types or
                log_input.indicators.get('file_hashes')):
            areas.append("execution_techniques")

        # Persistence: File operations, system modifications
        if (log_input.file_operations or
            'file_access' in log_input.event_types or
            any('modified' in str(log_input.file_operations).lower() for _ in [1]) if log_input.file_operations else False):
            areas.append("persistence_techniques")

        # Privilege Escalation: Authentication events, admin accounts
        if ('authentication_failure' in log_input.event_types or
                'authentication_success' in log_input.event_types or
                any('admin' in account.lower() for account in log_input.user_accounts) or
                any('domain' in source.lower() for source in log_input.log_sources)):
            areas.append("privilege_escalation_techniques")

        # Defense Evasion: PowerShell, encoded commands, security bypass
        if (any('powershell' in proc.lower() for proc in log_input.processes) or
                any('bypass' in anom['description'].lower() for anom in log_input.detected_anomalies) or
                any('encoded' in anom['description'].lower() for anom in log_input.detected_anomalies)):
            areas.append("defense_evasion_techniques")

        # Credential Access: Authentication failures, credential-related activities
        if ('authentication_failure' in log_input.event_types or
                any('credential' in anom['description'].lower() for anom in log_input.detected_anomalies) or
                any('login' in anom['description'].lower() for anom in log_input.detected_anomalies)):
            areas.append("credential_access_techniques")

        # Discovery: File access patterns, system enumeration
        if ('file_access' in log_input.event_types or
                log_input.file_operations and log_input.file_operations.get('created_files', 0) > 5):
            areas.append("discovery_techniques")

        # Lateral Movement: Multiple affected systems, network activity
        if (len(log_input.affected_systems) > 2 or
                log_input.network_activity and log_input.network_activity.get('external_connections', 0) > 10):
            areas.append("lateral_movement_techniques")

        # Collection: Large file operations, data access
        if (log_input.file_operations and
                (log_input.file_operations.get('created_files', 0) > 3 or
                 log_input.file_operations.get('modified_files', 0) > 5) or
                any('sensitive' in anom['description'].lower() for anom in log_input.detected_anomalies)):
            areas.append("collection_techniques")

        # Command and Control: External connections, unusual ports
        if (log_input.network_activity or
                'network_connection' in log_input.event_types or
                log_input.indicators.get('ips') or
                log_input.indicators.get('domains')):
            areas.append("command_control_techniques")

        # Exfiltration: Large data transfers, external connections
        if (log_input.network_activity and
                log_input.network_activity.get('data_transfer_gb', 0) > 1.0 or
                'data_transfer' in log_input.event_types):
            areas.append("exfiltration_techniques")

        # Impact: Critical severity, multiple systems affected
        if (log_input.severity == SeverityLevel.CRITICAL or
                len(log_input.affected_systems) > 3):
            areas.append("impact_techniques")

        # Ensure we have at least some core areas for any incident
        if not areas:
            areas = ["execution_techniques", "command_control_techniques", "persistence_techniques"]

        return areas

    def _determine_search_strategy(self, log_input: MitreAgentInput) -> str:
        """Determine best search strategy based on input characteristics."""
        # For high-severity incidents with specific indicators, use hybrid
        if log_input.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
            return "hybrid"

        # For threat hunting with many processes/files, use BM25 for exact matches
        if log_input.analysis_type == AnalysisType.THREAT_HUNTING and (log_input.processes or log_input.file_operations):
            return "bm25"

        # Default to hybrid for balanced results
        return "hybrid"

    def _determine_expected_tactics(self, log_input: MitreAgentInput) -> List[str]:
        """Determine expected tactics based on analysis type."""
        tactic_mappings = {
            AnalysisType.INCIDENT_RESPONSE: ['initial-access', 'execution', 'persistence', 'impact'],
            AnalysisType.THREAT_HUNTING: ['persistence', 'defense-evasion', 'credential-access'],
            AnalysisType.ANOMALY_DETECTION: ['execution', 'command-and-control', 'exfiltration'],
            AnalysisType.COMPLIANCE_CHECK: ['defense-evasion', 'persistence']
        }

        return tactic_mappings.get(log_input.analysis_type, [])

    def execute_planned_queries(self, log_input: MitreAgentInput, plan: Dict, retriever: MitreRetriever) -> Dict[str, Any]:
        """Execute queries for each priority area using the planned search strategy."""
        results = {}
        search_method = plan["search_strategy"]

        for area in plan["priority_areas"]:
            print(f"[INFO] Analyzing priority area: {area} using {search_method} search")

            query = self._generate_area_query(area, log_input)

            # Use query transformation
            transformed_queries = self.query_generator.transform_query(query, log_input)

            area_techniques = []
            for t_query in transformed_queries:
                # Use the planned search method
                if search_method == "hybrid":
                    techniques = retriever.hybrid_search(t_query, k=5)
                elif search_method == "bm25":
                    techniques = retriever.bm25_search(t_query, k=5)
                elif search_method == "semantic":
                    techniques = retriever.semantic_search(t_query, k=5)
                else:
                    techniques = retriever.hybrid_search(t_query, k=5)

                area_techniques.extend(techniques)

            # Deduplicate by attack_id
            unique_techniques = {}
            for tech in area_techniques:
                unique_techniques[tech['attack_id']] = tech

            results[area] = {
                "techniques": list(unique_techniques.values()),
                "queries_used": transformed_queries,
                "technique_count": len(unique_techniques),
                "search_method": search_method
            }

        return results

    def _generate_area_query(self, area: str, log_input: MitreAgentInput) -> str:
        """Generate contextual queries that leverage incident-specific details."""

        # Build context from actual incident data
        context_terms = []

        # Extract key terms from anomalies
        for anomaly in log_input.detected_anomalies:
            desc = anomaly.get('description', '').lower()
            # Extract meaningful keywords
            key_words = [word for word in desc.split()
                         if len(word) > 3 and word not in ['the', 'and', 'for', 'with', 'this', 'that']]
            context_terms.extend(key_words[:3])  # Top 3 words per anomaly

        # Core area-specific terms
        area_cores = {
            "initial_access_techniques": ["initial access", "entry point", "attack vector"],
            "execution_techniques": ["code execution", "process execution", "malware execution"],
            "persistence_techniques": ["persistence", "maintain access", "foothold"],
            "privilege_escalation_techniques": ["privilege escalation", "elevated privileges", "admin rights"],
            "defense_evasion_techniques": ["defense evasion", "bypass security", "avoid detection"],
            "credential_access_techniques": ["credential access", "password", "authentication"],
            "discovery_techniques": ["system discovery", "reconnaissance", "enumeration"],
            "lateral_movement_techniques": ["lateral movement", "spread", "move laterally"],
            "collection_techniques": ["data collection", "gather information", "collect files"],
            "command_control_techniques": ["command control", "remote access", "communication"],
            "exfiltration_techniques": ["data exfiltration", "steal data", "data theft"],
            "impact_techniques": ["system impact", "damage", "disruption"]
        }

        # Incident-specific contextual mapping
        query_parts = []

        # Add core area terms
        query_parts.extend(area_cores.get(area, [area.replace('_', ' ')]))

        # Add incident-specific context based on area
        if area == "initial_access_techniques":
            if any('email' in event for event in log_input.event_types):
                query_parts.extend(["email attack", "phishing", "malicious attachment"])
            if log_input.indicators.get('domains'):
                query_parts.extend(["malicious domain", "suspicious website"])
            if any('browser' in proc.lower() for proc in log_input.processes):
                query_parts.extend(["browser exploit", "drive-by download"])

        elif area == "execution_techniques":
            if any('powershell' in proc.lower() for proc in log_input.processes):
                query_parts.extend(["powershell execution", "script execution"])
            if any('cmd' in proc.lower() for proc in log_input.processes):
                query_parts.extend(["command line", "shell commands"])
            if log_input.indicators.get('file_hashes'):
                query_parts.extend(["malicious file", "executable"])

        elif area == "persistence_techniques":
            if log_input.file_operations:
                query_parts.extend(["file modification", "registry changes"])
            if any('service' in desc.lower() for anomaly in log_input.detected_anomalies
                   for desc in [anomaly.get('description', '')]):
                query_parts.extend(["service persistence", "scheduled task"])

        elif area == "privilege_escalation_techniques":
            if any('admin' in account.lower() for account in log_input.user_accounts):
                query_parts.extend(["admin account", "elevated access"])
            if 'authentication_failure' in log_input.event_types:
                query_parts.extend(["authentication bypass", "privilege abuse"])

        elif area == "defense_evasion_techniques":
            if any('obfuscat' in desc.lower() for anomaly in log_input.detected_anomalies
                   for desc in [anomaly.get('description', '')]):
                query_parts.extend(["code obfuscation", "encoding"])
            if any('bypass' in desc.lower() for anomaly in log_input.detected_anomalies
                   for desc in [anomaly.get('description', '')]):
                query_parts.extend(["security bypass", "evasion technique"])

        elif area == "credential_access_techniques":
            if 'authentication_failure' in log_input.event_types:
                query_parts.extend(["credential theft", "password attack"])
            if any('dump' in desc.lower() for anomaly in log_input.detected_anomalies
                   for desc in [anomaly.get('description', '')]):
                query_parts.extend(["credential dumping", "memory extraction"])

        elif area == "command_control_techniques":
            if log_input.network_activity:
                query_parts.extend(["network communication", "remote control"])
            if log_input.indicators.get('ips'):
                query_parts.extend(["external connection", "C2 communication"])
            if log_input.indicators.get('domains'):
                query_parts.extend(["command server", "control channel"])

            if hasattr(log_input, 'network_ports') or any('port' in str(log_input.network_activity).lower() for _ in [1]):
                query_parts.extend(["unusual ports", "non-standard ports", "custom protocols"])

            if any(tool in proc.lower() for proc in log_input.processes
                   for tool in ['teamviewer', 'anydesk', 'logmein', 'remote']):
                query_parts.extend(["remote access tool", "RAT"])

        elif area == "exfiltration_techniques":
            if (log_input.network_activity and
                    log_input.network_activity.get('data_transfer_gb', 0) > 1.0):
                query_parts.extend(["large data transfer", "data stealing"])
            if log_input.indicators.get('domains'):
                query_parts.extend(["external data transfer", "upload data"])

        # Add relevant processes as context
        relevant_processes = [proc for proc in log_input.processes[:3]
                              if any(keyword in proc.lower()
                                     for keyword in ['powershell', 'cmd', 'winword', 'excel', 'rundll'])]
        if relevant_processes:
            query_parts.extend(relevant_processes)

        # Add most relevant context terms from anomalies
        if context_terms:
            # Filter and add most relevant terms
            filtered_context = [term for term in context_terms[:5]
                                if len(term) > 4 and term.isalpha()]
            query_parts.extend(filtered_context)

        # Build final query with emphasis on most important terms
        core_query = " ".join(area_cores.get(area, [area.replace('_', ' ')]))
        context_query = " ".join(query_parts[len(area_cores.get(area, [])):])

        # Prioritize core area terms, then add context
        if context_query:
            final_query = f"{core_query} {context_query}"
        else:
            final_query = core_query

        # Limit query length to avoid noise
        words = final_query.split()
        if len(words) > 15:
            final_query = " ".join(words[:15])

        return final_query

    def generate_reasoning_trace(self, log_input: MitreAgentInput, plan: Dict, results: Dict) -> List[str]:
        """Generate a reasoning trace for transparency."""
        trace = []

        trace.append(f"1. Analyzed {log_input.analysis_type.value} with {log_input.severity.value} severity")
        trace.append(f"2. Selected {plan['search_strategy']} search strategy based on input characteristics")
        trace.append(f"3. Identified {len(plan['priority_areas'])} priority areas: {', '.join(plan['priority_areas'])}")

        total_techniques = sum(r['technique_count'] for r in results.values())
        trace.append(f"4. Retrieved {total_techniques} unique techniques across all areas")

        for area, result in results.items():
            top_tech = result['techniques'][0] if result['techniques'] else None
            if top_tech:
                trace.append(f"5. {area}: Top technique is {top_tech['attack_id']} - {top_tech['name']}")

        trace.append(f"6. Applied query transformation and {plan['search_strategy']} search for comprehensive coverage")

        return trace

if __name__ == "__main__":
    from mitre_query_generator import MitreQueryGenerator
    from mitre_example_input import create_sample_log_input
    from mitre_retriever import MitreRetriever

    print("Testing MitreAnalysisPlanner...")
    print("="*60)

    # Initialize components
    query_generator = MitreQueryGenerator()
    planner = MitreAnalysisPlanner(query_generator)
    retriever = MitreRetriever()

    # Create test data
    sample_input = create_sample_log_input()

    print(f"Testing with input: {sample_input.analysis_id}")
    print(f"Analysis type: {sample_input.analysis_type.value}")
    print(f"Severity: {sample_input.severity.value}")
    print(f"Processes: {sample_input.processes}")
    print(f"Log sources: {sample_input.log_sources}")

    # Test plan creation
    print(f"\n" + "="*40)
    print("Testing plan creation...")

    plan = planner.create_analysis_plan(sample_input)

    print(f"\nGenerated Plan:")
    print(f"- Objective: {plan['objective']}")
    print(f"- Priority areas: {plan['priority_areas']}")
    print(f"- Search strategy: {plan['search_strategy']}")
    print(f"- Expected tactics: {plan['expected_tactics']}")

    # Test priority area identification
    print(f"\n" + "="*30)
    print("Testing priority area identification...")
    priority_areas = planner._identify_priority_areas(sample_input)
    print(f"Priority areas identified: {priority_areas}")

    # Test search strategy determination
    search_strategy = planner._determine_search_strategy(sample_input)
    print(f"Search strategy: {search_strategy}")

    # Test expected tactics
    expected_tactics = planner._determine_expected_tactics(sample_input)
    print(f"Expected tactics: {expected_tactics}")

    # Test planned query execution
    print(f"\n" + "="*40)
    print("Testing planned query execution...")

    try:
        planned_results = planner.execute_planned_queries(sample_input, plan, retriever)

        print(f"\nPlanned execution results:")
        for area, result in planned_results.items():
            print(f"- {area}: {result['technique_count']} techniques, {len(result['queries_used'])} queries")
            if result['techniques']:
                top_tech = result['techniques'][0]
                print(f"  Top technique: {top_tech['attack_id']} - {top_tech['name']}")
    except Exception as e:
        print(f"Error in planned execution: {e}")

    # Test reasoning trace generation
    print(f"\n" + "="*40)
    print("Testing reasoning trace generation...")

    # Create mock results for trace
    mock_results = {
        'execution_techniques': {
            'techniques': [{'attack_id': 'T1055', 'name': 'Process Injection'}],
            'technique_count': 1
        }
    }

    reasoning_trace = planner.generate_reasoning_trace(sample_input, plan, mock_results)

    print(f"\nReasoning trace ({len(reasoning_trace)} steps):")
    for i, step in enumerate(reasoning_trace, 1):
        print(f"  {i}. {step}")

    # Test area query generation
    print(f"\n" + "="*30)
    print("Testing area query generation...")

    for area in ['execution_techniques', 'network_techniques', 'credential_techniques']:
        query = planner._generate_area_query(area, sample_input)
        print(f"- {area}: '{query}'")