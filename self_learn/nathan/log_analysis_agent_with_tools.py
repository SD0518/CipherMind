#python self_learn\nguyen\log_analysis_agent\log_analysis_agent_with_tools.py self_learn\nguyen\mordor_dataset\collection_host.json
import json
import os
import argparse
import sys
import re
from datetime import datetime
from dotenv import load_dotenv
from langchain_core.prompts import PromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field
from typing import List, Optional
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


class ToolsLogAnalysisAgent:
    def __init__(self):
        # Load environment variables
        env_path = os.path.join(os.path.dirname(__file__), '.env')
        load_dotenv(dotenv_path=env_path)
        
        self.api_key = os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not found. Please set it in .env file or environment variable.")

        # Initialize LLM
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-1.5-flash", 
            google_api_key=self.api_key,
            temperature=0.1,
            max_output_tokens=3000
        )

        # Initialize tools
        self.shodan_tool = ShodanTool()
        self.virustotal_tool = VirusTotalTool()

        # Set up output parser
        self.parser = JsonOutputParser(pydantic_object=LogAnalysisResult)

        # Create analysis prompt
        self.analysis_prompt = PromptTemplate(
            template=LOG_AGENT_PROMPT + "\n\n{format_instructions}\n\nLOG DATA TO ANALYZE:\n{log_data}",
            input_variables=["log_data"],
            partial_variables={"format_instructions": self.parser.get_format_instructions()}
        )

        # Create enrichment decision prompt
        self.enrichment_prompt = PromptTemplate(
            template="""
You are a cybersecurity analyst. Review the analysis results below and decide if any IOCs need enrichment.

ANALYSIS RESULTS:
{analysis_results}

Look for:
- IP addresses that might benefit from Shodan lookup (infrastructure details)
- IP addresses or file hashes that might benefit from VirusTotal lookup (reputation)

Respond with ONLY a JSON object in this format:
{{
    "needs_enrichment": true/false,
    "iocs_to_enrich": [
        {{"type": "ip", "value": "1.2.3.4", "tool": "shodan"}},
        {{"type": "hash", "value": "abc123...", "tool": "virustotal"}},
        {{"type": "ip", "value": "5.6.7.8", "tool": "virustotal"}}
    ]
}}
""",
            input_variables=["analysis_results"]
        )

    def load_logs_from_file(self, file_path: str) -> str:
        """Load logs from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            return content
        except FileNotFoundError:
            raise FileNotFoundError(f"Log file not found: {file_path}")
        except Exception as e:
            raise Exception(f"Error loading logs: {e}")

    def prepare_log_data(self, raw_content: str) -> str:
        """Prepare log data for analysis - handle large files intelligently"""
        line_count = raw_content.count('\n')
        
        # For large files, sample from beginning, middle, and end
        if len(raw_content) > 20000:
            first_part = raw_content[:7000]
            middle_start = len(raw_content) // 2 - 3000
            middle_part = raw_content[middle_start:middle_start + 6000]
            last_part = raw_content[-7000:]
            
            sampled_content = (
                f"{first_part}\n\n"
                f"... [SAMPLING FROM MIDDLE OF FILE] ...\n\n"
                f"{middle_part}\n\n"
                f"... [SAMPLING FROM END OF FILE] ...\n\n"
                f"{last_part}"
            )
            
            log_text = f"TOTAL LINES: {line_count}\nFILE SIZE: {len(raw_content)} characters\nANALYZING SAMPLES FROM BEGINNING, MIDDLE, AND END\n\n{sampled_content}"
        else:
            log_text = f"TOTAL LINES: {line_count}\n\n{raw_content}"
        
        return log_text

    def analyze_logs_initial(self, log_data: str) -> dict:
        """Initial log analysis without tools"""
        try:
            print("Performing initial log analysis...")
            
            # Get initial analysis
            formatted_prompt = self.analysis_prompt.format(log_data=log_data)
            response = self.llm.invoke(formatted_prompt)
            
            # Parse response
            content = response.content
            if "```json" in content:
                json_start = content.find("```json") + 7
                json_end = content.find("```", json_start)
                json_content = content[json_start:json_end].strip()
            else:
                json_content = content
            
            result = json.loads(json_content)
            return result
            
        except Exception as e:
            print(f"Error in initial analysis: {e}")
            return {
                "overall_assessment": "ABNORMAL",
                "total_events_analyzed": 1,
                "analysis_summary": f"Initial analysis failed: {e}",
                "abnormal_event_ids": [],
                "abnormal_events": []
            }

    def decide_enrichment(self, analysis_result: dict) -> dict:
        """Decide if enrichment is needed and which IOCs to enrich"""
        try:
            print("Deciding if enrichment is needed...")
            
            # Format the enrichment decision prompt
            formatted_prompt = self.enrichment_prompt.format(
                analysis_results=json.dumps(analysis_result, indent=2)
            )
            response = self.llm.invoke(formatted_prompt)
            
            # Parse response
            content = response.content
            if "```json" in content:
                json_start = content.find("```json") + 7
                json_end = content.find("```", json_start)
                json_content = content[json_start:json_end].strip()
            else:
                json_content = content
            
            enrichment_decision = json.loads(json_content)
            return enrichment_decision
            
        except Exception as e:
            print(f"Error in enrichment decision: {e}")
            return {"needs_enrichment": False, "iocs_to_enrich": []}

    def enrich_iocs(self, iocs_to_enrich: list) -> dict:
        """Enrich IOCs using appropriate tools"""
        enrichment_data = {}
        
        for ioc_info in iocs_to_enrich:
            ioc_value = ioc_info.get("value")
            tool_name = ioc_info.get("tool")
            ioc_type = ioc_info.get("type")
            
            # Clean hash values by removing prefixes like "SHA1=", "MD5=", etc.
            if ioc_type == "hash" and "=" in ioc_value:
                clean_ioc = ioc_value.split("=", 1)[1]
            else:
                clean_ioc = ioc_value
            
            print(f"Enriching {ioc_type} {clean_ioc} with {tool_name}...")
            
            try:
                if tool_name == "shodan":
                    result = self.shodan_tool.run({"ioc": clean_ioc})
                elif tool_name == "virustotal":
                    result = self.virustotal_tool.run({"ioc": clean_ioc})
                else:
                    result = {"error": f"Unknown tool: {tool_name}"}
                
                enrichment_data[f"{tool_name}_{ioc_value}"] = result
                
            except Exception as e:
                enrichment_data[f"{tool_name}_{ioc_value}"] = {"error": str(e)}
        
        return enrichment_data

    def final_analysis_with_enrichment(self, log_data: str, initial_analysis: dict, enrichment_data: dict) -> dict:
        """Final analysis incorporating enrichment data"""
        try:
            print("Performing final analysis with enrichment data...")
            
            # Create final analysis prompt
            final_prompt = f"""
{LOG_AGENT_PROMPT}

You have completed an initial analysis and received enrichment data from external tools.
Incorporate the enrichment data into your final analysis.

INITIAL ANALYSIS:
{json.dumps(initial_analysis, indent=2)}

ENRICHMENT DATA:
{json.dumps(enrichment_data, indent=2)}

Provide your final analysis incorporating the enrichment data. Update the "why_abnormal" explanations 
and "indicators" lists to include insights from the tool results.

{self.parser.get_format_instructions()}

LOG DATA:
{log_data}
"""
            
            response = self.llm.invoke(final_prompt)
            
            # Parse response
            content = response.content
            if "```json" in content:
                json_start = content.find("```json") + 7
                json_end = content.find("```", json_start)
                json_content = content[json_start:json_end].strip()
            else:
                json_content = content
            
            result = json.loads(json_content)
            
            # Add enrichment data to events
            for event in result.get("abnormal_events", []):
                event["tool_enrichment"] = enrichment_data
            
            return result
            
        except Exception as e:
            print(f"Error in final analysis: {e}")
            # Return initial analysis as fallback
            return initial_analysis

    def run_analysis(self, log_file_path: str, output_path: str = None) -> dict:
        """Main analysis workflow"""
        try:
            print(f"Starting Log Analysis Agent with Tools")
            print(f"Loading logs from: {log_file_path}")
            
            # Load and prepare log data
            raw_content = self.load_logs_from_file(log_file_path)
            log_data = self.prepare_log_data(raw_content)
            
            line_count = raw_content.count('\n')
            print(f"Loaded file with {line_count} lines and {len(raw_content)} characters")
            
            # Step 1: Initial analysis
            initial_result = self.analyze_logs_initial(log_data)
            
            # Step 2: Decide if enrichment is needed
            enrichment_decision = self.decide_enrichment(initial_result)
            
            # Step 3: Enrich if needed
            if enrichment_decision.get("needs_enrichment", False):
                print("Enrichment needed - calling external tools...")
                enrichment_data = self.enrich_iocs(enrichment_decision.get("iocs_to_enrich", []))
                
                # Step 4: Final analysis with enrichment
                final_result = self.final_analysis_with_enrichment(log_data, initial_result, enrichment_data)
            else:
                print("No enrichment needed - using initial analysis")
                final_result = initial_result
            
            # Always save results automatically
            self.save_analysis_result(final_result, log_file_path)
            
            # Display results
            self.display_results(final_result)
            
            return final_result
            
        except Exception as e:
            error_msg = f"Analysis failed: {e}"
            print(error_msg)
            return {"error": error_msg}


    def save_analysis_result(self, result: dict, input_file_path: str):
        """Save analysis result to predefined analysis subfolder"""
        try:
            # Get the input filename without extension
            input_filename = os.path.basename(input_file_path)
            input_name = os.path.splitext(input_filename)[0]

            # Map input file name to target analysis subfolder
            analysis_subfolder = input_name  # assumes dataset names match analysis folders

            # Create absolute path to analysis directory
            # First get the project root directory (parent of self_learn)
            script_dir = os.path.dirname(os.path.abspath(__file__))  # log_analysis_agent folder
            nguyen_dir = os.path.dirname(script_dir)  # nguyen folder
            self_learn_dir = os.path.dirname(nguyen_dir)  # self_learn folder
            
            # Create full folder path
            analysis_dir = os.path.join(nguyen_dir, "analysis", analysis_subfolder)
            print(f"Saving analysis to directory: {analysis_dir}")
            os.makedirs(analysis_dir, exist_ok=True)

            # Generate output filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"{analysis_subfolder}_analysis_{timestamp}.json"
            output_path = os.path.join(analysis_dir, output_filename)

            # Save result
            with open(output_path, 'w', encoding='utf-8') as file:
                json.dump(result, file, indent=2)

            print(f"Analysis saved to: {output_path}")
            return output_path

        except Exception as e:
            print(f"Error saving results: {e}")
            return None



    def display_results(self, result: dict):
        """Display analysis results in a user-friendly format"""
        try:
            print("\n" + "="*70)
            print("SIMPLE TOOLS CYBERSECURITY ANALYSIS RESULTS")
            print("="*70)
            
            # Overall assessment
            assessment = result.get('overall_assessment', 'UNKNOWN')
            print(f"OVERALL ASSESSMENT: {assessment}")
            print(f"Total Events Analyzed: {result.get('total_events_analyzed', 'N/A')}")
            print(f"Summary: {result.get('analysis_summary', 'N/A')}")
            
            # Abnormal event IDs summary
            abnormal_ids = result.get('abnormal_event_ids', [])
            if abnormal_ids:
                print(f"\nABNORMAL Windows Event IDs ({len(abnormal_ids)}): {', '.join(map(str, abnormal_ids))}")
            
            # Abnormal events
            abnormal_events = result.get('abnormal_events', [])
            if abnormal_events:
                print(f"\nABNORMAL EVENTS DETECTED ({len(abnormal_events)}):")
                for i, event in enumerate(abnormal_events, 1):
                    print(f"\n  EVENT {i} - {event.get('severity', 'UNKNOWN')} SEVERITY")
                    print(f"     Windows Event ID: {event.get('event_id', 'N/A')}")
                    print(f"     What: {event.get('event_description', 'N/A')}")
                    print(f"     Why Abnormal: {event.get('why_abnormal', 'N/A')}")
                    print(f"     Potential Threat: {event.get('potential_threat', 'N/A')}")
                    
                    category = event.get('attack_category', '')
                    if category:
                        print(f"     Attack Category: {category}")
                    
                    indicators = event.get('indicators', [])
                    if indicators:
                        print(f"     Technical Indicators ({len(indicators)}):")
                        for indicator in indicators:
                            print(f"       • {indicator}")
                    
                    # Display tool enrichment if available
                    tool_enrichment = event.get('tool_enrichment', {})
                    if tool_enrichment:
                        print(f"     Tool Enrichment:")
                        for key, value in tool_enrichment.items():
                            if isinstance(value, dict) and 'result' in value:
                                print(f"       • {key}: {value['result']}")
                            else:
                                print(f"       • {key}: {value}")
            else:
                print("\nNo abnormal events detected")
            
            print("\n" + "="*70)
            
        except Exception as e:
            print(f"Error displaying results: {e}")
            print("Raw result:", result)


def main():
    parser = argparse.ArgumentParser(description='Simple Tools Cybersecurity Log Analysis Agent')
    parser.add_argument('log_file', help='Path to log file (any format: JSON, JSONL, CSV, txt)')
    parser.add_argument('-o', '--output', help='Output file path (optional)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        # Initialize agent
        agent = ToolsLogAnalysisAgent()
        
        # Run analysis
        result = agent.run_analysis(args.log_file, args.output)
        
        print(f"\nSimple Tools Agent execution completed!")
        
    except ValueError as e:
        print(f"Setup Error: {e}")
        print("Get your free Gemini API key at: https://aistudio.google.com/app/apikey")
        sys.exit(1)
    except Exception as e:
        print(f"Execution Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
