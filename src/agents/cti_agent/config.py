# Search configuration
CTI_SEARCH_CONFIG = {
    "max_results": 5,
    "search_depth": "advanced",
    "include_raw_content": True,
    "include_domains": [
        "*.cisa.gov",  # US Cybersecurity and Infrastructure Security Agency
        "*.us-cert.gov",  # US-CERT advisories
        "*.crowdstrike.com",  # CrowdStrike threat intelligence
        "*.mandiant.com",  # Mandiant (Google) threat reports
        "*.trendmicro.com",  # Trend Micro research
        "*.securelist.com",  # Kaspersky SecureList blog
        "*.cert.europa.eu",  # European CERT
        "*.ncsc.gov.uk",  # UK National Cyber Security Centre
    ],
}


# Model configuration
MODEL_NAME = "google_genai:gemini-2.0-flash"

# CTI Planner Prompt
CTI_PLANNER_PROMPT = """You are a Cyber Threat Intelligence (CTI) researcher planning 
to retrieve actual threat intelligence from CTI reports.

Your goal is to create a research plan that finds CTI reports and EXTRACTS the actual 
intelligence - specific IOCs, technique details, actor information, and attack patterns.

IMPORTANT GUIDELINES:
1. Search for actual CTI reports from reputable sources
2. Prioritize recent reports (2024-2025)
3. ALWAYS fetch full report content to extract intelligence
4. Extract SPECIFIC intelligence: actual IOCs, technique IDs, actor names, attack details
5. Focus on retrieving CONCRETE DATA that can be used by other analysis agents
6. Maximum 4 tasks with only one time of web searching

Available tools:
(1) SearchCTIReports[query]: Searches for CTI reports, threat analyses, and security advisories.
    - More specific search queries (add APT names, CVE IDs, "IOC", "MITRE", "report")
    - Use specific queries with APT names, technique IDs, CVEs
    - Examples: "APT29 T1566.002 report 2025", "Scattered Spider IOCs"

(2) ExtractURL[search_result, index]: Extract a specific URL from search results JSON.
    - search_result: JSON string from SearchCTIReports
    - index: Which report URL to extract (default: 0 for first)
    - ALWAYS use this to get the actual report URL from search results

(3) FetchReport[url]: Retrieves the full content of a CTI report using real url.
    - ALWAYS use this to get actual report content for intelligence extraction
    - Essential for retrieving specific IOCs and details

(4) ExtractIOCs[report_content]: Extracts actual Indicators of Compromise from reports.
    - Returns specific IPs, domains, hashes, URLs, file names
    - Provides concrete IOCs that can be used for detection

(5) IdentifyThreatActors[report_content]: Extracts threat actor details from reports.
    - Returns specific actor names, aliases, and campaign names
    - Provides attribution information and targeting details
    - Includes motivation and operational patterns

(6) ExtractMITRETechniques[report_content, framework]: Extracts MITRE ATT&CK techniques from reports.
    - framework: "Enterprise", "Mobile", or "ICS" (default: "Enterprise")
    - Returns specific technique IDs (T1234) with descriptions
    - Maps malware behaviors to MITRE framework
    - Provides structured technique analysis

(7) LLM[instruction]: Synthesis and correlation of extracted intelligence.
    - Combine intelligence from multiple sources
    - DON'T USE FOR ANY OTHER PURPOSES
    - Identify patterns across findings
    - Correlate IOCs with techniques and actors

PLAN STRUCTURE:
Each plan step should be: Plan: [description] #E[N] = Tool[input]

Example for task "Find threat intelligence about APT29 using T1566.002":

Plan: Search for recent APT29 campaign reports with IOCs
#E1 = SearchCTIReports[APT29 T1566.002 spearphishing IOCs 2025]

Plan: Search for detailed technical analysis of APT29 spearphishing
#E2 = SearchCTIReports[APT29 spearphishing technical analysis filetype:pdf]

Plan: Fetch the most detailed technical report for intelligence extraction
#E3 = FetchReport[top ranked URL from #E1 with most technical detail]

Plan: Extract all specific IOCs from the fetched report
#E4 = ExtractIOCs[#E3]

Plan: Extract threat actor details and campaign information from the report
#E5 = IdentifyThreatActors[#E3]

Plan: If first report lacks detail, fetch second report for additional intelligence
#E6 = FetchReport[second best URL from #E1]

Plan: Extract IOCs from second report to enrich intelligence
#E7 = ExtractIOCs[#E7]

Plan: Correlate and consolidate all extracted intelligence
#E8 = LLM[Consolidate intelligence from #E4, #E5, #E6, and #E8. Present specific 
IOCs, technique IDs, actor details, and attack patterns. Identify overlaps and unique findings.]

Now create a detailed plan for the following task:
Task: {task}"""

# CTI Solver Prompt
CTI_SOLVER_PROMPT = """You are a Cyber Threat Intelligence analyst creating a final intelligence report.

Below are the COMPLETE results from your CTI research. Each section contains the full output from extraction tools.

{structured_results}

{'='*80}
EXECUTION PLAN OVERVIEW:
{'='*80}
{plan}

{'='*80}
ORIGINAL TASK: {task}
{'='*80}

Create a comprehensive threat intelligence report with the following structure:

## Intelligence Sources
[List reports analyzed with titles and sources]

## Threat Actors & Attribution
[Names, aliases, campaigns, and attribution details from IdentifyThreatActors results]

## MITRE ATT&CK Techniques Identified
[All technique IDs from ExtractMITRETechniques results, with descriptions]

## Indicators of Compromise (IOCs) Retrieved
[All IOCs from ExtractIOCs results, organized by type]

### IP Addresses
### Domains  
### File Hashes
### URLs
### Email Addresses
### File Names
### Other Indicators

## Attack Patterns & Campaign Details
[Specific attack flows, timeline, targeting from reports]

## Key Findings Summary
[3-5 critical bullet points]

## Intelligence Gaps
[What information was not available]

**INSTRUCTIONS:**
- Extract ALL data from results above - don't summarize, list actual values
- Parse JSON if present in results
- If Q&A format, extract all answers
- Be comprehensive and specific
"""

# Regex pattern for parsing CTI plans
CTI_REGEX_PATTERN = r"Plan:\s*(.+)\s*(#E\d+)\s*=\s*(\w+)\s*\[([^\]]+)\]"

# Tool-specific prompts
IOC_EXTRACTION_PROMPT = """Extract all Indicators of Compromise (IOCs) from the content below.

**Instructions:** List ONLY the actual IOCs found. No explanations, no summaries - just the indicators.

**Content:**
{content}

**Extract and list:**

**IP Addresses:**
[List IPs, or write "None found"]

**Domains:**
[List domains, or write "None found"]

**URLs:**
[List malicious URLs, or write "None found"]

**File Hashes:**
[List hashes with type (MD5/SHA1/SHA256), or write "None found"]

**Email Addresses:**
[List emails, or write "None found"]

**File Names:**
[List malicious files/paths, or write "None found"]

**Registry Keys:**
[List registry keys, or write "None found"]

**Other Indicators:**
[List mutexes, user agents, etc., or write "None found"]

If no specific IOCs found, respond: "No extractable IOCs in content."
"""

THREAT_ACTOR_PROMPT = """Extract threat actor information from the content below.

**Instructions:** Provide concise answers. Include brief descriptions where relevant.

**Content:**
{content}

**Answer these questions:**

**Q: What threat actor/APT group is discussed?**
A: [Name and aliases, e.g., "APT29 (Cozy Bear, The Dukes)" or "None identified"]

**Q: What is this actor known for?**
A: [1-2 sentence description of their typical activities/focus, or "No attribution details"]

**Q: What campaigns/operations are mentioned?**
A: [List campaign names with timeframes, e.g., "NobleBaron (2024-Q2)" or "None mentioned"]

**Q: What is their suspected origin/attribution?**
A: [Nation-state/origin and confidence level, e.g., "Russian state-sponsored (High confidence)" or "Unknown"]

**Q: Who/what do they target?**
A: [Industries and regions, e.g., "Government agencies in Europe, Defense sector in North America" or "Not specified"]

**Q: What is their motivation?**
A: [Primary objective, e.g., "Espionage and intelligence collection" or "Not specified"]

If no specific threat actor information found, respond: "No threat actor attribution in content."
"""

REPLAN_PROMPT = """The previous CTI research step failed to retrieve quality intelligence.

ORIGINAL TASK: {task}

FAILED STEP:
Plan: {failed_step}
{step_name} = {tool}[{tool_input}]

RESULT: {results}

PROBLEM: {problem}

COMPLETED STEPS SO FAR:
{completed_steps}

Create an IMPROVED plan for this specific step that will retrieve ACTUAL CTI intelligence.

Available tools:
(1) SearchCTIReports[query]: Searches for CTI reports, threat analyses, and security advisories.
    - Use specific queries with APT names, technique IDs, CVEs
    - Examples: "APT29 T1566.002 report 2024", "Scattered Spider IOCs"

(2) ExtractURL[search_result, index]: Extract a specific URL from search results JSON.
    - search_result: JSON string from SearchCTIReports
    - index: Which report URL to extract (default: 0 for first)
    - ALWAYS use this to get the actual report URL from search results

(3) FetchReport[url]: Retrieves the full content of a CTI report.
    - ALWAYS use this to get actual report content for intelligence extraction
    - Essential for retrieving specific IOCs and details

(4) ExtractIOCs[report_content]: Extracts actual Indicators of Compromise from reports.
    - Returns specific IPs, domains, hashes, URLs, file names
    - Provides concrete IOCs that can be used for detection

(5) IdentifyThreatActors[report_content]: Extracts threat actor details from reports.
    - Returns specific actor names, aliases, and campaign names
    - Provides attribution information and targeting details
    - Includes motivation and operational patterns
    
(6) ExtractMITRETechniques[report_content, framework]: Extracts MITRE ATT&CK techniques from reports.
    - framework: "Enterprise", "Mobile", or "ICS" (default: "Enterprise")
    - Returns specific technique IDs (T1234) with descriptions
    - Maps malware behaviors to MITRE framework
    - Provides structured technique analysis

(7) LLM[instruction]: Synthesis and correlation of extracted intelligence.
    - Combine intelligence from multiple sources
    - Identify patterns across findings
    - Correlate IOCs with techniques and actors

Consider:
1. More specific search queries (add APT names, CVE IDs, "IOC", "MITRE", "report")
2. Alternative CTI sources (CISA advisories, vendor reports, not news articles)
3. Different tool combinations (search → extract URL → fetch → extract IOCs)

Provide ONLY the corrected step in this format:
Plan: [improved description]
#E{step} = Tool[improved input]"""

MITRE_EXTRACTION_PROMPT = """Extract MITRE ATT&CK {framework} techniques from the content below.

**Instructions:** 
1. Identify behaviors described in the content
2. Map to MITRE technique IDs (main techniques only: T#### not T####.###)
3. Provide brief description of what each technique means
4. List final technique IDs on the last line

**Content:**
{content}

**Identified Techniques:**

[For each technique found, format as:]
**T####** - [Technique Name]: [1 sentence: what this technique is and why it was identified in the content]

[Continue for all techniques...]

**Final Answer - Technique IDs:**
T####, T####, T####

[If no valid techniques found, respond: "No MITRE {framework} techniques identified in content."]
"""

REPLAN_PROMPT = """The previous CTI research step failed to retrieve quality intelligence.

ORIGINAL TASK: {task}

FAILED STEP:
Plan: {failed_step}
{step_name} = {tool}[{tool_input}]

RESULT: {results}

PROBLEM: {problem}

COMPLETED STEPS SO FAR:
{completed_steps}

Create an IMPROVED plan for this specific step that will retrieve ACTUAL CTI intelligence.

Available tools:
(1) SearchCTIReports[query]: Searches for CTI reports, threat analyses, and security advisories.
    - Use specific queries with APT names, technique IDs, CVEs
    - Examples: "APT29 T1566.002 report 2024", "Scattered Spider IOCs"

(2) ExtractURL[search_result, index]: Extract a specific URL from search results JSON.
    - search_result: JSON string from SearchCTIReports
    - index: Which report URL to extract (default: 0 for first)
    - ALWAYS use this to get the actual report URL from search results

(3) FetchReport[url]: Retrieves the full content of a CTI report.
    - ALWAYS use this to get actual report content for intelligence extraction
    - Essential for retrieving specific IOCs and details

(4) ExtractIOCs[report_content]: Extracts actual Indicators of Compromise from reports.
    - Returns specific IPs, domains, hashes, URLs, file names
    - Provides concrete IOCs that can be used for detection

(5) IdentifyThreatActors[report_content]: Extracts threat actor details from reports.
    - Returns specific actor names, aliases, and campaign names
    - Provides attribution information and targeting details
    - Includes motivation and operational patterns

(6) ExtractMITRETechniques[report_content, framework]: Extracts MITRE ATT&CK techniques from reports.
    - framework: "Enterprise", "Mobile", or "ICS" (default: "Enterprise")
    - Returns specific technique IDs (T1234) with descriptions
    - Maps malware behaviors to MITRE framework

(7) LLM[instruction]: Synthesis and correlation of extracted intelligence.
    - Combine intelligence from multiple sources
    - Identify patterns across findings
    - Correlate IOCs with techniques and actors

Consider:
1. More specific search queries (add APT names, CVE IDs, "IOC", "MITRE", "report")
2. Alternative CTI sources (CISA advisories, vendor reports, not news articles)
3. Different tool combinations (search → extract URL → fetch → extract IOCs/techniques)

Provide ONLY the corrected step in this format:
Plan: [improved description]
#E{step} = Tool[improved input]"""
