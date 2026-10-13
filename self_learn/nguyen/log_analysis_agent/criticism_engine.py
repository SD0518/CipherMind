import json
from prompts import SELF_CRITIC_PROMPT

def self_critic_review(llm, state: dict) -> dict:
    """Run self-critic review with quality evaluation"""
    critic_input = SELF_CRITIC_PROMPT.format(
        final_json=json.dumps(state["analysis_result"], indent=2),
        messages="\n".join([str(m.content) for m in state["messages"] if hasattr(m, "content")]),
        logs=state["prepared_logs"]
    )

    resp = llm.invoke(critic_input)
    full_response = resp.content
    
    try:
        # Parse critic response
        quality_acceptable, issues, feedback, corrected_json = _parse_critic_response(full_response)
        
        return {
            "quality_acceptable": quality_acceptable,
            "issues": issues,
            "feedback": feedback,
            "corrected_analysis": corrected_json,
            "full_response": full_response
        }
    except Exception as e:
        print(f"[Critic] Failed to parse review: {e}")
        # If critic fails, accept current analysis
        return {
            "quality_acceptable": True,
            "issues": [],
            "feedback": "",
            "corrected_analysis": state["analysis_result"],
            "full_response": full_response
        }

def _parse_critic_response(content: str) -> tuple:
    """Parse critic response and evaluate quality"""
    
    # Extract sections
    issues_section = ""
    feedback_section = ""
    
    if "## ISSUES FOUND" in content:
        parts = content.split("## ISSUES FOUND")
        if len(parts) > 1:
            issues_part = parts[1].split("##")[0].strip()
            issues_section = issues_part
    
    if "## FEEDBACK FOR AGENT" in content:
        parts = content.split("## FEEDBACK FOR AGENT")
        if len(parts) > 1:
            feedback_part = parts[1].split("##")[0].strip()
            feedback_section = feedback_part
    
    # Extract corrected JSON
    if "```json" in content:
        json_str = content.split("```json")[1].split("```")[0].strip()
    elif "```" in content:
        json_str = content.split("```")[1].split("```")[0].strip()
    else:
        json_str = "{}"
    
    corrected_json = json.loads(json_str)
    
    # Evaluate quality based on issues
    issues = _extract_issues(issues_section)
    quality_acceptable = _evaluate_quality(issues, issues_section)
    
    return quality_acceptable, issues, feedback_section, corrected_json

def _extract_issues(issues_text: str) -> list:
    """Extract structured issues from text"""
    issues = []
    
    # Check for "None" or "no issues"
    if "none" in issues_text.lower() and "analysis is acceptable" in issues_text.lower():
        return issues
    
    # Extract issue types
    issue_types = {
        "MISSING_EVENT_IDS": "missing_event_ids",
        "SEVERITY_MISMATCH": "severity_mismatch",
        "IGNORED_TOOLS": "ignored_tool_results",
        "INCOMPLETE_EVENTS": "incomplete_abnormal_events",
        "EVENT_ID_FORMAT": "event_id_format",
        "SCHEMA_ISSUES": "schema_issues",
        "UNDECODED_COMMANDS": "undecoded_commands"
    }
    
    for keyword, issue_type in issue_types.items():
        if keyword in issues_text:
            issues.append({"type": issue_type, "text": issues_text})
    
    return issues

def _evaluate_quality(issues: list, issues_text: str) -> bool:
    """
    Evaluate if quality is acceptable.
    Extensible - easy to add new criteria here.
    """
    # If no issues found
    if not issues:
        return True
    
    # Critical issue types that trigger iteration
    critical_types = {
        'missing_event_ids',
        'severity_mismatch',
        'ignored_tool_results',
        'incomplete_abnormal_events',
        'undecoded_commands'
    }
    
    # Count critical issues
    critical_count = sum(1 for issue in issues if issue['type'] in critical_types)
    
    # Quality threshold: max 1 critical issue is acceptable
    if critical_count >= 2:
        return False
    
    # Additional check: if issues_text indicates major problems
    if any(word in issues_text.lower() for word in ['critical', 'major', 'serious']):
        return False
    
    return True