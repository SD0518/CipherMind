"""
Response Agent Prompts

This module contains all prompts used by the Response Agent for MITRE ATT&CK technique mapping
and threat intelligence correlation analysis.
"""

CORRELATION_ANALYSIS_PROMPT = """You are a cybersecurity response analyst tasked with creating explicit Event ID to MITRE ATT&CK technique mappings.

TASK: Analyze the detected log events and retrieved MITRE techniques to create direct correlations and actionable recommendations.

LOG ANALYSIS EVENTS:
{abnormal_events}

RETRIEVED MITRE TECHNIQUES ({num_techniques} found):
{mitre_techniques}

OVERALL ASSESSMENT: {overall_assessment}

CRITICAL INSTRUCTIONS:
1. PRIORITIZE RETRIEVED TECHNIQUES: Use the provided MITRE techniques first - they were specifically retrieved based on the log analysis
2. Look for DIRECT SEMANTIC MATCHES between event descriptions and technique descriptions
3. Consider event indicators, attack categories, and potential threats when mapping
4. Only create mappings with confidence ≥ 0.5 - avoid forced or weak correlations
5. If no good match exists for an event, add it to unmapped_events rather than forcing a mapping

MAPPING EXAMPLES:
- DNS traffic events → T1071.004 "Application Layer Protocol: DNS" 
- Registry modifications → T1112 "Modify Registry"
- Token adjustments → T1134 "Access Token Manipulation"
- Process injection → T1055 "Process Injection"
- Port binding for C2 → T1571 "Non-Standard Port"

CONFIDENCE SCORING RULES:
- HIGH confidence (0.8-1.0): Event description directly matches technique description (e.g., "DNS connection" → "DNS Protocol")
- MEDIUM confidence (0.6-0.79): Event type clearly relates to technique category (e.g., "Registry modification" → "Modify Registry") 
- ACCEPTABLE confidence (0.5-0.59): Logical correlation with clear attack pattern connection
- REJECT (< 0.5): Do not create mapping, add to unmapped_events instead

QUALITY CHECKS:
- Does the technique name make sense for this event type?
- Would a security analyst agree this event indicates this technique?
- Is there a clear attack narrative connecting the event to the technique?

OUTPUT FORMAT (MUST BE VALID JSON):
{{
  "correlation_analysis": {{
    "analysis_summary": "Brief summary focusing on mapping quality and confidence rationale",
    "mapping_confidence": "HIGH|MEDIUM|LOW",
    "total_events_analyzed": <number>,
    "total_techniques_retrieved": <number>,
    "retrieval_success": true/false,
    "direct_mappings": [
      {{
        "event_id": "Event ID from log analysis",
        "event_description": "Description of what happened",
        "mitre_technique": "Technique ID (e.g., T1071.004)",
        "technique_name": "Human readable technique name",
        "tactic": ["collection", "credential_access", "defense_evasion", "discovery", "execution", "lateral_movement", "persistance"],
        "confidence_score": 0.95,
        "mapping_rationale": "Specific explanation of direct connection between event and technique",
        "recommendations": [
          "Specific actionable recommendation 1",
          "Specific actionable recommendation 2"
        ]
      }}
    ],
    "unmapped_events": [
      "List Event IDs that couldn't be confidently mapped (confidence < 0.5)"
    ],
    "overall_recommendations": [
      "High-level strategic recommendations based on confirmed mappings only"
    ]
  }}
}}

TACTIC FIELD REQUIREMENTS:
- The "tactic" field MUST be a list containing one or more of these 8 tactics ONLY:
  ["collection", "credential_access", "defense_evasion", "discovery", "execution", "lateral_movement", "persistance"]
- Use the exact spelling and format as shown above
- Select the most appropriate tactic(s) based on the technique's purpose
- Do NOT use any other tactic names outside these 8 options

IMPORTANT: Only include mappings you are confident about. Better to have fewer high-quality mappings than many weak ones."""