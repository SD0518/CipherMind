"""
Response Agent - Maps Event IDs to MITRE ATT&CK Techniques and Generates Recommendations

This agent analyzes log analysis results and retrieval intelligence to create explicit
Event ID → MITRE technique mappings with actionable recommendations.
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple
from langchain.chat_models import init_chat_model

# Import prompts from the separate file
from src.agents.response_agent.prompts import CORRELATION_ANALYSIS_PROMPT


class ResponseAgent:
    """
    Response Agent that creates explicit Event ID to MITRE technique mappings
    and generates actionable recommendations based on correlation analysis.
    """

    def __init__(
        self,
        model_name: str = "google_genai:gemini-2.0-flash",
        temperature: float = 0.1,
        output_dir: str = "final_response",
        llm_client=None,
    ):
        """
        Initialize the Response Agent.

        Args:
            model_name: LLM model to use
            temperature: Temperature for generation
            output_dir: Directory to save final response JSON
            llm_client: Optional pre-initialized LLM client (overrides model_name/temperature)
        """
        if llm_client:
            self.llm = llm_client
            # Extract model name from llm_client if possible
            if hasattr(llm_client, "model_name"):
                self.model_name = llm_client.model_name
            else:
                # Fallback: try to extract from the model string
                self.model_name = (
                    str(llm_client).split("'")[1]
                    if "'" in str(llm_client)
                    else "unknown_model"
                )
            print(f"[INFO] Response Agent: Using provided LLM client")
        else:
            self.llm = init_chat_model(model_name, temperature=temperature)
            self.model_name = model_name
            print(f"[INFO] Response Agent: Using default LLM model: {model_name}")

        # Create model-specific output directory (strip provider prefixes like
        # "google_genai:" or "models/" so we only keep clean names such as
        # "gemini-2.0-flash" or "gemini-2.0-flash-lite")
        self.model_dir_name = self._sanitize_model_name(self.model_name)
        self.output_dir = Path(output_dir) / self.model_dir_name
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _sanitize_model_name(self, model_name: str) -> str:
        """
        Produce a clean model directory name without provider prefixes.

        Examples:
        - "google_genai:gemini-2.0-flash" -> "gemini-2.0-flash"
        - "google_genai:gemini-2.0-flash-lite" -> "gemini-2.0-flash-lite"
        - "models/gemini-2.0-flash-lite" -> "gemini-2.0-flash-lite"
        - "groq:gpt-oss-120b" -> "gpt-oss-120b"
        """
        raw = (model_name or "").strip()
        # Prefer the segment after ":" if present (provider:model)
        if ":" in raw:
            raw = raw.split(":", 1)[1]
        # Then prefer the last path segment after "/" if present (e.g., models/name)
        if "/" in raw or "\\" in raw:
            raw = raw.replace("\\", "/").split("/")[-1]

        # Final sanitation: allow only safe characters
        sanitized = "".join(c for c in raw if c.isalnum() or c in "._-")
        # Fallback in case the resulting name is empty
        return sanitized or "model"

    def analyze_and_map(
        self,
        log_analysis_result: Dict[str, Any],
        retrieval_result: Dict[str, Any],
        log_file: str,
        tactic: str = None,
    ) -> Dict[str, Any]:
        """
        Analyze log analysis and retrieval results to create Event ID mappings.

        Args:
            log_analysis_result: Results from log analysis agent
            retrieval_result: Results from retrieval supervisor
            log_file: Path to original log file
            tactic: Optional tactic name for organizing output

        Returns:
            Structured mapping analysis with recommendations
        """
        # Extract data for analysis
        abnormal_events = log_analysis_result.get("abnormal_events", [])
        overall_assessment = log_analysis_result.get("overall_assessment", "UNKNOWN")

        # Extract MITRE techniques from retrieval results with improved parsing
        mitre_techniques = self._extract_mitre_techniques(retrieval_result)

        # Pre-filter techniques based on semantic similarity
        relevant_techniques = self._filter_relevant_techniques(
            abnormal_events, mitre_techniques
        )

        # Create analysis prompt
        analysis_prompt = self._create_analysis_prompt(
            abnormal_events, relevant_techniques, overall_assessment
        )

        # Get LLM analysis
        response = self.llm.invoke(analysis_prompt)
        mapping_analysis = self._parse_response(response.content, log_analysis_result)

        # Add metadata
        mapping_analysis["metadata"] = {
            "analysis_timestamp": datetime.now().isoformat(),
            "overall_assessment": overall_assessment,
            "total_abnormal_events": len(abnormal_events),
            "total_techniques_retrieved": len(mitre_techniques),
        }

        # Save to JSON file
        output_path, markdown_report = self._save_response(
            mapping_analysis, log_file, tactic
        )

        return mapping_analysis, markdown_report

    def _extract_mitre_techniques(
        self, retrieval_result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Extract MITRE techniques from structured retrieval supervisor results."""

        # NEW APPROACH: Use structured results directly
        if "retrieved_techniques" in retrieval_result:
            techniques = retrieval_result["retrieved_techniques"]
            print(
                f"[INFO] Using structured retrieval results: {len(techniques)} techniques"
            )

            # Ensure all techniques have required fields
            validated_techniques = []
            for tech in techniques:
                # Ensure tactic is a list format
                tactic = tech.get("tactic", "")
                if isinstance(tactic, str):
                    # Convert string to list if it's a single tactic
                    tactic = [tactic] if tactic else []
                elif not isinstance(tactic, list):
                    tactic = []

                validated_tech = {
                    "technique_id": tech.get("technique_id", ""),
                    "technique_name": tech.get("technique_name", ""),
                    "tactic": tactic,
                    "description": tech.get("description", ""),
                    "relevance_score": tech.get("relevance_score", 0.5),
                }
                validated_techniques.append(validated_tech)

            return validated_techniques

        # FALLBACK: Legacy parsing for backward compatibility
        print("[WARNING] No structured results found, using legacy message parsing")
        return self._extract_mitre_techniques_legacy(retrieval_result)

    def _extract_mitre_techniques_legacy(
        self, retrieval_result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Legacy method to extract MITRE techniques from raw message history."""
        techniques = []

        messages = retrieval_result.get("messages", [])

        # PRIORITY STRATEGY: Extract from database agent tool messages
        # These contain the original tactic information before it's lost in formatting
        for msg in messages:
            # Look for tool messages from search_techniques calls
            if (
                hasattr(msg, "name")
                and msg.name
                and "search_techniques" in str(msg.name)
            ):
                if hasattr(msg, "content") and msg.content:
                    try:
                        # Parse the tool response
                        tool_data = (
                            json.loads(msg.content)
                            if isinstance(msg.content, str)
                            else msg.content
                        )

                        if "techniques" in tool_data:
                            for tech in tool_data["techniques"]:
                                # Convert tactics to list format
                                tactics = tech.get("tactics", [])
                                if isinstance(tactics, str):
                                    tactics = [tactics] if tactics else []
                                elif not isinstance(tactics, list):
                                    tactics = []

                                converted = {
                                    "technique_id": tech.get("attack_id", ""),
                                    "technique_name": tech.get("name", ""),
                                    "tactic": tactics,  # Now as list
                                    "platforms": ", ".join(tech.get("platforms", [])),
                                    "description": tech.get("description", ""),
                                    "relevance_score": tech.get("relevance_score", 0),
                                }
                                techniques.append(converted)
                    except (json.JSONDecodeError, TypeError, AttributeError):
                        continue

        # If we successfully extracted techniques with tactics, use them
        if techniques:
            print(
                f"[INFO] Extracted {len(techniques)} techniques with tactics from database agent"
            )
            # Remove duplicates
            unique_techniques = []
            seen_ids = set()
            for tech in techniques:
                tech_id = tech.get("technique_id")
                if tech_id and tech_id not in seen_ids:
                    seen_ids.add(tech_id)
                    unique_techniques.append(tech)
            return unique_techniques

        # FALLBACK: Use original extraction strategies
        print(
            "[WARNING] Could not extract techniques from tool messages, using fallback extraction"
        )

        # Strategy 1: Look for the final supervisor message with structured data
        for msg in reversed(messages):
            if hasattr(msg, "content") and msg.content:
                content = msg.content

                # Look for different possible JSON structures
                json_candidates = self._extract_json_from_content(content)

                for json_data in json_candidates:
                    # Try multiple extraction patterns
                    extracted = self._try_extraction_patterns(json_data)
                    if extracted:
                        techniques.extend(extracted)
                        break

                if techniques:
                    break

        # Strategy 2: Look for tool messages with technique data (already tried above)
        if not techniques:
            for msg in messages:
                if hasattr(msg, "name") and "database" in str(msg.name).lower():
                    if hasattr(msg, "content"):
                        tool_techniques = self._extract_from_tool_content(msg.content)
                        if tool_techniques:
                            techniques.extend(tool_techniques)

        # Strategy 3: Parse any structured content that looks like MITRE data
        if not techniques:
            for msg in messages:
                if hasattr(msg, "content") and msg.content:
                    general_techniques = self._extract_general_technique_mentions(
                        msg.content
                    )
                    if general_techniques:
                        techniques.extend(general_techniques)
                        break

        # Remove duplicates based on technique_id
        unique_techniques = []
        seen_ids = set()
        for tech in techniques:
            tech_id = (
                tech.get("technique_id") or tech.get("attack_id") or tech.get("id")
            )
            if tech_id and tech_id not in seen_ids:
                seen_ids.add(tech_id)
                unique_techniques.append(tech)

        return unique_techniques

    def _extract_json_from_content(self, content: str) -> List[Dict[str, Any]]:
        """Extract all possible JSON objects from content."""
        json_candidates = []

        # Look for JSON blocks
        if "```json" in content:
            json_blocks = content.split("```json")
            for block in json_blocks[1:]:
                json_str = block.split("```")[0].strip()
                try:
                    json_data = json.loads(json_str)
                    json_candidates.append(json_data)
                except json.JSONDecodeError:
                    continue

        # Look for any JSON-like structures
        start_idx = 0
        while True:
            start_idx = content.find("{", start_idx)
            if start_idx == -1:
                break

            # Find matching closing brace
            brace_count = 0
            end_idx = start_idx
            for i in range(start_idx, len(content)):
                if content[i] == "{":
                    brace_count += 1
                elif content[i] == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        end_idx = i + 1
                        break

            if brace_count == 0:
                json_str = content[start_idx:end_idx]
                try:
                    json_data = json.loads(json_str)
                    json_candidates.append(json_data)
                except json.JSONDecodeError:
                    pass

            start_idx += 1

        return json_candidates

    def _try_extraction_patterns(
        self, json_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Try different patterns to extract MITRE techniques from JSON data."""
        techniques = []

        # Pattern 1: Original expected format
        if "cybersecurity_intelligence" in json_data:
            threat_indicators = json_data["cybersecurity_intelligence"].get(
                "threat_indicators", []
            )
            for indicator in threat_indicators:
                mitre_techniques = indicator.get("mitre_attack_techniques", [])
                techniques.extend(mitre_techniques)

        # Pattern 2: Direct techniques list
        if "techniques" in json_data:
            techniques.extend(json_data["techniques"])

        # Pattern 3: MITRE techniques at root level
        if "mitre_techniques" in json_data:
            techniques.extend(json_data["mitre_techniques"])

        # Pattern 4: mitre_attack_techniques array
        if "mitre_attack_techniques" in json_data:
            techniques.extend(json_data["mitre_attack_techniques"])

        # Pattern 5: Database agent response format
        if "search_type" in json_data and "techniques" in json_data:
            for tech in json_data["techniques"]:
                # Convert database agent format to expected format
                # Convert tactics to list format
                tactics = tech.get("tactics", [])
                if isinstance(tactics, str):
                    tactics = [tactics] if tactics else []
                elif not isinstance(tactics, list):
                    tactics = []

                converted = {
                    "technique_id": tech.get("attack_id", ""),
                    "technique_name": tech.get("name", ""),
                    "tactic": tactics,  # Now as list
                    "description": tech.get("description", ""),
                }
                techniques.append(converted)

        # Pattern 6: Look for any structure with attack_id/technique_id
        def find_techniques_recursive(obj, path=""):
            found = []
            if isinstance(obj, dict):
                # Check if this looks like a technique
                if "technique_id" in obj and "technique_name" in obj:
                    # Ensure tactic is a list format
                    tactic = obj.get("tactic", "")
                    if isinstance(tactic, str):
                        tactic = [tactic] if tactic else []
                    elif not isinstance(tactic, list):
                        tactic = []

                    technique = {
                        "technique_id": obj.get("technique_id", ""),
                        "technique_name": obj.get("technique_name", ""),
                        "tactic": tactic,  # Now as list
                        "description": obj.get("description", ""),
                    }
                    found.append(technique)
                elif "attack_id" in obj:
                    # Convert tactics to list format
                    tactics = obj.get("tactics", [])
                    if isinstance(tactics, str):
                        tactics = [tactics] if tactics else []
                    elif not isinstance(tactics, list):
                        tactics = []

                    converted = {
                        "technique_id": obj.get("attack_id", ""),
                        "technique_name": obj.get("name", ""),
                        "tactic": tactics,  # Now as list
                        "description": obj.get("description", ""),
                    }
                    found.append(converted)

                # Recurse into nested objects
                for key, value in obj.items():
                    found.extend(find_techniques_recursive(value, f"{path}.{key}"))

            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    found.extend(find_techniques_recursive(item, f"{path}[{i}]"))

            return found

        techniques.extend(find_techniques_recursive(json_data))

        return techniques

    def _filter_relevant_techniques(
        self, abnormal_events: List[Dict], techniques: List[Dict]
    ) -> List[Dict]:
        """Filter techniques based on semantic relevance to events."""
        if not techniques or not abnormal_events:
            return techniques

        relevant_techniques = []

        # Extract keywords from events for matching
        event_keywords = set()
        for event in abnormal_events:
            desc = event.get("event_description", "").lower()
            indicators = [str(ind).lower() for ind in event.get("indicators", [])]
            category = event.get("attack_category", "").lower()
            threat = event.get("potential_threat", "").lower()

            # Add key terms
            event_keywords.update(desc.split())
            for ind in indicators:
                event_keywords.update(ind.split())
            if category:
                event_keywords.update(category.split())
            if threat:
                event_keywords.update(threat.split())

        # Score techniques based on keyword overlap
        for technique in techniques:
            tech_name = technique.get("technique_name", "").lower()
            tech_desc = technique.get("description", "").lower()
            tech_tactic = technique.get("tactic", [])

            # Convert tactics to string for keyword matching
            if isinstance(tech_tactic, list):
                tech_tactic_str = " ".join(tech_tactic).lower()
            else:
                tech_tactic_str = str(tech_tactic).lower()

            # Calculate relevance score
            tech_words = set(
                tech_name.split() + tech_desc.split() + tech_tactic_str.split()
            )
            overlap = len(event_keywords.intersection(tech_words))

            # Add technique if there's reasonable overlap or if it's a high-value technique
            if overlap > 0 or any(
                keyword in tech_name or keyword in tech_desc
                for keyword in [
                    "dns",
                    "registry",
                    "token",
                    "privilege",
                    "port",
                    "network",
                    "process",
                ]
            ):
                technique["relevance_score"] = overlap
                relevant_techniques.append(technique)

        # Sort by relevance score (descending) and return relevant techniques
        relevant_techniques.sort(
            key=lambda x: x.get("relevance_score", 0), reverse=True
        )

        # Dynamic filtering: return techniques with meaningful relevance or minimum threshold
        if relevant_techniques:
            # Keep techniques with score > 0 or important cybersecurity techniques
            filtered = [
                t for t in relevant_techniques if t.get("relevance_score", 0) > 0
            ]

            # If we filtered too aggressively, keep at least the most relevant ones
            if not filtered and relevant_techniques:
                filtered = relevant_techniques[: min(5, len(relevant_techniques))]

            # But don't overwhelm the LLM - if we have too many, keep the most relevant
            if len(filtered) > 15:  # Reasonable upper limit
                filtered = filtered[:15]

            return filtered

        return relevant_techniques  # Return all if no filtering worked

    def _extract_from_tool_content(self, content: str) -> List[Dict[str, Any]]:
        """Extract techniques from tool message content."""
        techniques = []

        # Try to parse as JSON first
        try:
            if isinstance(content, str):
                json_data = json.loads(content)
                techniques.extend(self._try_extraction_patterns(json_data))
        except json.JSONDecodeError:
            pass

        return techniques

    def _extract_general_technique_mentions(self, content: str) -> List[Dict[str, Any]]:
        """Extract technique mentions from general text content."""
        techniques = []

        # Look for MITRE technique patterns like T1234, T1234.001
        import re

        # Pattern for MITRE technique IDs
        technique_pattern = r"T\d{4}(?:\.\d{3})?"
        technique_matches = re.findall(technique_pattern, content)

        # Look for technique names in context
        for match in technique_matches:
            # Try to extract technique name from surrounding context
            pattern = rf"{re.escape(match)}[^.]*?([A-Z][a-zA-Z\s]+)"
            context_match = re.search(pattern, content)

            technique_name = ""
            if context_match:
                technique_name = context_match.group(1).strip()

            technique = {
                "technique_id": match,
                "technique_name": technique_name,
                "tactic": [],  # Empty list for unknown tactics
                "description": f"Technique {match} mentioned in retrieval results",
            }
            techniques.append(technique)

        return techniques

    def _calculate_bayesian_confidence(
        self, llm_confidence: float, event_severity: str, total_matched_techniques: int
    ) -> float:
        """
        Bayesian-inspired confidence calculation.

        Based on correlation agent's methodology with weighted factors:
        - Correlation (50%): LLM-assigned confidence score
        - Evidence (25%): Number and quality of matched techniques
        - Severity (25%): Event severity level

        Args:
            llm_confidence: Original confidence score from LLM (0.0-1.0)
            event_severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            total_matched_techniques: Total number of matched techniques

        Returns:
            Adjusted confidence score (0.0-0.95)
        """
        # Weight distribution based on cybersecurity research
        WEIGHTS = {
            "correlation": 0.50,  # Primary indicator - LLM confidence
            "evidence": 0.25,  # Evidence strength
            "severity": 0.25,  # Contextual severity
        }

        # Severity scores based on CVSS principles
        severity_scores = {"CRITICAL": 1.0, "HIGH": 0.85, "MEDIUM": 0.6, "LOW": 0.35}
        severity_component = severity_scores.get(event_severity.upper(), 0.6)

        # Evidence component with diminishing returns
        # More matched techniques increase confidence but with diminishing returns
        quantity_factor = min(1.0, 0.5 + (total_matched_techniques * 0.15))
        evidence_component = quantity_factor

        # Weighted combination
        bayesian_confidence = (
            WEIGHTS["correlation"] * llm_confidence
            + WEIGHTS["evidence"] * evidence_component
            + WEIGHTS["severity"] * severity_component
        )

        # Cap at 0.95 to avoid overconfidence bias
        bayesian_confidence = min(bayesian_confidence, 0.95)

        # Uncertainty penalty for single weak matches
        if total_matched_techniques == 1 and llm_confidence < 0.6:
            bayesian_confidence *= 0.8

        return round(bayesian_confidence, 3)

    def _create_analysis_prompt(
        self,
        abnormal_events: List[Dict],
        mitre_techniques: List[Dict],
        overall_assessment: str,
    ) -> str:
        """Create the analysis prompt for the LLM using the template from prompts.py."""

        return CORRELATION_ANALYSIS_PROMPT.format(
            abnormal_events=json.dumps(abnormal_events, indent=2),
            num_techniques=len(mitre_techniques),
            mitre_techniques=json.dumps(mitre_techniques, indent=2),
            overall_assessment=overall_assessment,
        )

    def _parse_response(
        self, response_content: str, log_analysis_result: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Parse the LLM response, extract JSON, and apply Bayesian confidence adjustment."""
        try:
            # Try to extract JSON from the response
            if "```json" in response_content:
                json_str = response_content.split("```json")[1].split("```")[0].strip()
            elif "```" in response_content:
                json_str = response_content.split("```")[1].split("```")[0].strip()
            else:
                # Look for JSON-like structure
                start_idx = response_content.find("{")
                end_idx = response_content.rfind("}") + 1
                if start_idx != -1 and end_idx > start_idx:
                    json_str = response_content[start_idx:end_idx]
                else:
                    json_str = response_content.strip()

            result = json.loads(json_str)

            # Apply Bayesian confidence adjustment to each mapping
            correlation_analysis = result.get("correlation_analysis", {})
            direct_mappings = correlation_analysis.get("direct_mappings", [])

            if direct_mappings and log_analysis_result:
                # Extract overall severity from log analysis
                overall_assessment = log_analysis_result.get(
                    "overall_assessment", "UNKNOWN"
                )

                # Map overall assessment to severity level
                assessment_to_severity = {
                    "NORMAL": "LOW",
                    "SUSPICIOUS": "MEDIUM",
                    "ABNORMAL": "HIGH",
                    "CRITICAL": "CRITICAL",
                }
                log_severity = assessment_to_severity.get(overall_assessment, "MEDIUM")

                total_matched = len(direct_mappings)

                # Apply Bayesian adjustment to each mapping
                for mapping in direct_mappings:
                    llm_confidence = mapping.get("confidence_score", 0.5)

                    # Calculate Bayesian-adjusted confidence
                    bayesian_confidence = self._calculate_bayesian_confidence(
                        llm_confidence=llm_confidence,
                        event_severity=log_severity,
                        total_matched_techniques=total_matched,
                    )

                    # Store adjusted confidence (overwrite original)
                    mapping["confidence_score"] = bayesian_confidence

                    # Optionally store original for debugging (can remove this)
                    mapping["_original_llm_confidence"] = llm_confidence

            return result

        except json.JSONDecodeError as e:
            print(f"[WARNING] Failed to parse LLM response as JSON: {e}")
            # Return a fallback structure
            return {
                "correlation_analysis": {
                    "analysis_summary": "Failed to parse response - manual review required",
                    "mapping_confidence": "LOW",
                    "total_events_analyzed": 0,
                    "total_techniques_retrieved": 0,
                    "retrieval_success": False,
                    "direct_mappings": [],
                    "unmapped_events": [],
                    "overall_recommendations": [
                        "Review raw response for manual analysis"
                    ],
                },
                "raw_response": response_content,
            }

    def _save_response(
        self, mapping_analysis: Dict[str, Any], log_file: str, tactic: str = None
    ) -> Tuple[str, str]:
        """Save the response analysis to both JSON and Markdown files."""
        # Generate folder and filenames based on log file
        log_filename = Path(log_file).stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create tactic-specific subdirectory if tactic is provided
        if tactic:
            base_output_dir = self.output_dir / tactic
            base_output_dir.mkdir(exist_ok=True)
        else:
            base_output_dir = self.output_dir

        # Create subfolder with log name and timestamp
        output_folder = base_output_dir / f"{log_filename}_{timestamp}"
        output_folder.mkdir(exist_ok=True)

        # File paths - use shorter, more readable names
        json_filename = "response_analysis.json"
        md_filename = "threat_report.md"

        json_path = output_folder / json_filename
        md_path = output_folder / md_filename

        try:
            # Save JSON file
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(mapping_analysis, f, indent=2, ensure_ascii=False)

            # Generate and save Markdown report
            markdown_report = self._generate_markdown_report(
                mapping_analysis, log_filename
            )
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(markdown_report)

            return str(output_folder), markdown_report.strip()

        except Exception as e:
            print(f"[ERROR] Failed to save response analysis: {e}")
            return "", ""  # Return empty strings for both paths and report

    def _generate_markdown_report(
        self, mapping_analysis: Dict[str, Any], log_filename: str
    ) -> str:
        """Generate a nicely formatted Markdown threat intelligence report."""
        correlation = mapping_analysis.get("correlation_analysis", {})
        metadata = mapping_analysis.get("metadata", {})

        # Start building the Markdown content
        md = []

        # Header
        md.append("# Cybersecurity Threat Intelligence Report\n")
        md.append("---\n")

        # Metadata section
        md.append("## Report Metadata\n")
        md.append(f"- **Log File:** `{log_filename}`\n")
        md.append(
            f"- **Analysis Date:** {metadata.get('analysis_timestamp', 'Unknown')[:19].replace('T', ' ')}\n"
        )

        # Overall assessment with colored badge
        assessment = metadata.get("overall_assessment", "Unknown")
        assessment_badge = {
            "NORMAL": "NORMAL",
            "SUSPICIOUS": "SUSPICIOUS",
            "ABNORMAL": "ABNORMAL",
            "CRITICAL": "CRITICAL",
        }.get(assessment, assessment)

        md.append(f"- **Overall Assessment:** {assessment_badge}\n")
        md.append(
            f"- **Events Analyzed:** {correlation.get('total_events_analyzed', 0)}\n"
        )
        md.append(
            f"- **MITRE Techniques Retrieved:** {correlation.get('total_techniques_retrieved', 0)}\n"
        )

        # Mapping confidence with badge
        confidence = correlation.get("mapping_confidence", "Unknown")
        confidence_badge = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(
            confidence, confidence
        )

        md.append(f"- **Mapping Confidence:** {confidence_badge}\n")
        md.append("\n---\n")

        # Executive Summary
        md.append("## Executive Summary\n")
        md.append(f"{correlation.get('analysis_summary', 'No summary available')}\n")
        md.append("\n---\n")

        # Event-to-Technique Mappings
        mappings = correlation.get("direct_mappings", [])
        if mappings:
            md.append("## Threat Analysis - Event to MITRE ATT&CK Mappings\n")

            for i, mapping in enumerate(mappings, 1):
                event_id = mapping.get("event_id", "Unknown")
                event_desc = mapping.get("event_description", "No description")
                technique = mapping.get("mitre_technique", "Unknown")
                technique_name = mapping.get("technique_name", "Unknown")
                tactic = mapping.get("tactic", [])
                # Convert tactic list to string for display
                if isinstance(tactic, list):
                    tactic_str = ", ".join(tactic) if tactic else "Unknown"
                else:
                    tactic_str = str(tactic) if tactic else "Unknown"
                confidence = mapping.get("confidence_score", 0)
                rationale = mapping.get("mapping_rationale", "No rationale provided")

                # Confidence badge
                if confidence >= 0.8:
                    confidence_badge = f"HIGH ({confidence:.2f})"
                elif confidence >= 0.6:
                    confidence_badge = f"MEDIUM ({confidence:.2f})"
                else:
                    confidence_badge = f"LOW ({confidence:.2f})"

                md.append(f"### {i}. Event ID: {event_id}\n")
                md.append(f"**Event Description:** {event_desc}\n\n")
                md.append(
                    f"#### MITRE Technique: [{technique}](https://attack.mitre.org/techniques/{technique.replace('.', '/')}/)\n"
                )
                md.append(f"- **Technique Name:** {technique_name}\n")
                md.append(f"- **Tactic:** {tactic_str}\n")
                md.append(f"- **Confidence:** {confidence_badge}\n")
                md.append("\n")

                md.append(f"**Analysis:**\n")
                md.append(f"> {rationale}\n")
                md.append("\n")

                # Recommendations
                recommendations = mapping.get("recommendations", [])
                if recommendations:
                    md.append("**Immediate Actions:**\n")
                    for j, rec in enumerate(recommendations, 1):
                        md.append(f"{j}. {rec}\n")
                    md.append("\n")

                md.append("---\n")

        # Unmapped Events
        unmapped = correlation.get("unmapped_events", [])
        if unmapped:
            md.append("## Unmapped Events\n")
            md.append(
                "The following events could not be confidently mapped to MITRE techniques:\n\n"
            )
            for event_id in unmapped:
                md.append(f"- Event ID: `{event_id}`\n")
            md.append(
                "\n> **Note:** These events may require manual analysis or additional context.\n"
            )
            md.append("\n---\n")

        # Priority Matrix
        if mappings:
            high_priority = [m for m in mappings if m.get("confidence_score", 0) >= 0.7]
            medium_priority = [
                m for m in mappings if 0.5 <= m.get("confidence_score", 0) < 0.7
            ]
            low_priority = [m for m in mappings if m.get("confidence_score", 0) < 0.5]

            md.append("## Priority Matrix\n")

            if high_priority:
                md.append("### HIGH PRIORITY (Investigate Immediately)\n")
                md.append(
                    "| Event ID | MITRE Technique | Technique Name | Confidence |\n"
                )
                md.append(
                    "|----------|-----------------|----------------|------------|\n"
                )
                for mapping in high_priority:
                    event_id = mapping.get("event_id", "Unknown")
                    technique = mapping.get("mitre_technique", "Unknown")
                    name = mapping.get("technique_name", "Unknown")
                    conf = mapping.get("confidence_score", 0)
                    md.append(f"| {event_id} | {technique} | {name} | {conf:.2f} |\n")
                md.append("\n")

            if medium_priority:
                md.append("### MEDIUM PRIORITY (Monitor and Investigate)\n")
                md.append(
                    "| Event ID | MITRE Technique | Technique Name | Confidence |\n"
                )
                md.append(
                    "|----------|-----------------|----------------|------------|\n"
                )
                for mapping in medium_priority:
                    event_id = mapping.get("event_id", "Unknown")
                    technique = mapping.get("mitre_technique", "Unknown")
                    name = mapping.get("technique_name", "Unknown")
                    conf = mapping.get("confidence_score", 0)
                    md.append(f"| {event_id} | {technique} | {name} | {conf:.2f} |\n")
                md.append("\n")

            if low_priority:
                md.append("### LOW PRIORITY (Review as Needed)\n")
                md.append(
                    "| Event ID | MITRE Technique | Technique Name | Confidence |\n"
                )
                md.append(
                    "|----------|-----------------|----------------|------------|\n"
                )
                for mapping in low_priority:
                    event_id = mapping.get("event_id", "Unknown")
                    technique = mapping.get("mitre_technique", "Unknown")
                    name = mapping.get("technique_name", "Unknown")
                    conf = mapping.get("confidence_score", 0)
                    md.append(f"| {event_id} | {technique} | {name} | {conf:.2f} |\n")
                md.append("\n")

            md.append("---\n")

        # Strategic Recommendations
        overall_recs = correlation.get("overall_recommendations", [])
        if overall_recs:
            md.append("## Strategic Recommendations\n")
            for i, rec in enumerate(overall_recs, 1):
                md.append(f"{i}. {rec}\n")
            md.append("\n---\n")

        # Footer
        md.append("## Additional Information\n")
        md.append(
            "- **Report Format:** This report provides event-to-technique correlation analysis\n"
        )
        md.append(
            "- **Technical Details:** See the accompanying JSON file for complete technical data\n"
        )
        md.append(
            "- **MITRE ATT&CK:** Click technique IDs above to view full details on the MITRE ATT&CK website\n"
        )
        md.append("\n")
        md.append("---\n")
        md.append("*Report generated by Cybersecurity Multi-Agent Pipeline*\n")

        return "".join(md)

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the response agent."""
        return {
            "agent_type": "Response Agent",
            "model": (
                self.llm.model_name if hasattr(self.llm, "model_name") else "Unknown"
            ),
            "output_directory": str(self.output_dir),
            "version": "1.2",
        }


# Test function for the Response Agent
def test_response_agent():
    """Test the Response Agent with sample data."""

    # Sample log analysis result
    sample_log_analysis = {
        "overall_assessment": "SUSPICIOUS",
        "abnormal_events": [
            {
                "event_id": "5156",
                "event_description": "DNS connection to external IP 64.4.48.201",
                "severity": "HIGH",
                "indicators": ["dns.exe", "64.4.48.201"],
            },
            {
                "event_id": "10",
                "event_description": "Token right adjustment for MORDORDC$",
                "severity": "HIGH",
                "indicators": ["svchost.exe", "token adjustment"],
            },
        ],
    }

    # Sample retrieval result (simplified)
    sample_retrieval = {
        "messages": [
            type(
                "MockMessage",
                (),
                {
                    "content": """{"cybersecurity_intelligence": {
                    "threat_indicators": [
                        {
                            "mitre_attack_techniques": [
                                {
                                    "technique_id": "T1071.004",
                                    "technique_name": "DNS",
                                    "tactic": "Command and Control"
                                },
                                {
                                    "technique_id": "T1134",
                                    "technique_name": "Access Token Manipulation", 
                                    "tactic": "Privilege Escalation"
                                }
                            ]
                        }
                    ]
                }}"""
                },
            )()
        ]
    }

    # Initialize and test the agent
    agent = ResponseAgent()
    result = agent.analyze_and_map(
        sample_log_analysis, sample_retrieval, "test_sample.json"
    )

    print("\nTest completed!")
    print(f"Analysis result keys: {list(result.keys())}")


if __name__ == "__main__":
    test_response_agent()
